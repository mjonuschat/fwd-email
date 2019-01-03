#!/usr/bin/env python3
import asyncio
from collections import ChainMap
from logging import Logger, getLogger
from typing import Dict, List, Optional, Set

import dkim
import idna
import spf
from aiodns import DNSResolver
from aiosmtpd.smtp import SMTP, Envelope, Session
from aiosmtplib.errors import (
    SMTPConnectError,
    SMTPException,
    SMTPResponseException,
    SMTPServerDisconnected,
    SMTPTimeoutError,
)
from aiosmtplib.smtp import SMTP as SMTPClient
from asyncache import cached
from blacklist import blocklist as blacklisted_domains
from cachetools import TTLCache
from disposable_email_domains import blocklist as disposable_domains
from flanker import mime
from flanker.addresslib.address import EmailAddress
from flanker.addresslib.address import parse as parse_address
from flanker.mime.message.headers import MimeHeaders
from flanker.mime.message.part import MimePart
from fqdn import FQDN
from pydnsbl import DNSBLChecker
from pydnsbl.checker import DNSBLResult


class ForwardHandler:
    """
    Handler for inbound messages that proxies messages to configurable destionations.
    """

    FORWARDING_ADDRESSES: Dict[str, Set[str]] = {
        "sharks-with-lasers.net": {"mail:mjonuschat@gmail.com|morton@jonuschat.de"}
    }

    SANITIZE_HEADER_FIELDS = ["dkim-signature", "x-google-dkim-signature"]

    def __init__(self):
        """
        Initializer
        """
        self._loop = asyncio.get_event_loop()
        self._logger = getLogger("mail.log")

    @property
    def log(self) -> Logger:
        """
        Returns the logger instance.
        """
        return self._logger

    @property
    def loop(self) -> asyncio.events.AbstractEventLoop:
        """
        Returns the currently running asyncio loop.
        """
        return self._loop

    @loop.setter
    def loop(self, loop: asyncio.events.AbstractEventLoop):
        """
        Set the currently running asyncio loop from the controller.
        """
        self._loop = loop

    async def handle_HELO(
        self, _server: SMTP, session: Session, _envelope: Envelope, hostname: str
    ) -> str:
        """
        Handle DATA commands

        Args:
            _server:
            session:
            _envelope:
            hostname: The remote hostname as given in HELO/EHLO statement.

        Returns:
            SMTP response as string
        """
        fqdn = FQDN(fqdn=hostname)
        if not fqdn.is_valid:
            self.log.debug("%s is not a valid FQDN", hostname)
            return f"550 {hostname} is not a FQDN"

        is_blacklisted = await self._check_dnsbl(ip=session.peer[0])
        if is_blacklisted:
            self.log.debug("%s is listed in one or more DNSBL", session.peer[0])
            return f"550 {session.peer[0]} is not welcome here"

        session.host_name = fqdn.relative
        return f"250 {fqdn.relative}"

    async def handle_EHLO(
        self, _server: SMTP, session: Session, _envelope: Envelope, hostname: str
    ) -> str:
        """
        Handle DATA commands

        Args:
            _server:
            session:
            _envelope:
            hostname: The remote hostname as given in HELO/EHLO statement.

        Returns:
            SMTP response as string
        """
        fqdn = FQDN(fqdn=hostname)
        if not fqdn.is_valid:
            self.log.debug("%s is not a valid FQDN", hostname)
            return f"550 {hostname} is not a FQDN"

        is_blacklisted = await self._check_dnsbl(ip=session.peer[0])
        if is_blacklisted:
            self.log.debug("%s is listed in one or more DNSBL", session.peer[0])
            return f"550 {session.peer[0]} is not welcome here"

        session.host_name = fqdn.relative
        return f"250 HELP"

    async def handle_MAIL(
        self,
        _server: SMTP,
        _session: Session,
        envelope: Envelope,
        address: str,
        mail_options: List[str],
    ) -> str:
        """
        Handle SMTP MAIL FROM commands

        Args:
            _server:
            _session:
            envelope:
            address:
            mail_options:

        Returns:

        """
        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(
        self,
        _server: SMTP,
        _session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: List[str],
    ) -> str:
        """
        Handle RCPT TO commands

        Args:
            _server:
            _session:
            envelope:
            address:
            rcpt_options:

        Returns:
            SMTP response as string
        """
        rcpt: EmailAddress = parse_address(address)
        if rcpt is None:
            self.log.debug("Could not parse %s", address)
            return f"550 {address} could not be parsed"

        try:
            # Validate that we have a destination for the address
            destinations = await self._get_forwarding_addresses(rcpt=rcpt)
            envelope.rcpt_tos.append({address: destinations})
            envelope.rcpt_options.extend(rcpt_options)
        except SMTPResponseException as e:
            self.log.exception("Error handling RCPT TO command", e.message)
            return f"{e.code} {e.message}"

        return "250 OK"

    async def handle_DATA(
        self, _server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        """
        Handle DATA commands

        Args:
            _server:
            session:
            envelope:

        Returns:
            SMTP response as string
        """

        msg: MimePart = mime.from_string(envelope.content)
        headers: MimeHeaders = msg.headers

        self.log.info("Forwarding message to %s", envelope.rcpt_tos)

        try:
            mail_from = ""
            sender: EmailAddress = parse_address(envelope.mail_from)
            if sender is not None:
                mail_from = sender.address

            self.log.info("Using sender information: %s", mail_from)

            # SPF Validation
            spf_result, spf_explanation = spf.check2(
                i=session.peer[0], s=mail_from, h=session.host_name
            )
            self.log.debug(
                "SPF result for %s/%s/%s: %s (%s)",
                session.peer[0],
                mail_from,
                session.host_name,
                spf_result,
                spf_explanation,
            )

            # DKIM validation
            dkim_ok = dkim.verify(message=msg.to_string().encode("utf-8"))
            self.log.debug("DKIM validation result: %s", str(dkim_ok))

            if not dkim_ok and spf_result in ["none", "fail", "permerror"]:
                self.log.info("Rejecting message, neither SPF nor DKIM configured")
                raise SMTPResponseException(
                    code=550,
                    message=(
                        "Please ensure you have either SPF or DKIM set up "
                        "for the domain you're sending from."
                    ),
                )

            # TODO: SPAMD integration: aiospamc

            # Remove headers conflicting with DKIM re-signing
            for field in self.SANITIZE_HEADER_FIELDS:
                if field not in headers:
                    continue
                self.log.debug("Removing header %s before forwarding message", field)
                del headers[field]

            # TODO: DMARC support

            result = await asyncio.gather(
                *[
                    self._send_message(mail_from, rcpt, msg)
                    for rcpt in set.union(*ChainMap(*envelope.rcpt_tos).values())
                ],
                loop=self.loop,
            )
            print(result)
        except SMTPResponseException as e:
            self.log.exception("Error forwarding message: %s %s", e.code, e.message)
            return f"{e.code} {e.message}"

        self.log.info("Message forwarded to %s", envelope.rcpt_tos)
        return "250 OK"

    async def _send_message(
        self, sender: str, rcpt: EmailAddress, msg: MimePart
    ) -> str:
        """
        Send an email over SMTP.

        Args:
            sender: The sender address of the message in mailbox@domain.tld format
            rcpt: The recipient ofthe message.
            msg: The message to be sent
        """
        smtp_servers = await self._get_mx_records(domain=rcpt.hostname)
        if not smtp_servers:
            self.log.debug("Could not resolve mail exchangers for %s", rcpt.hostname)
            raise SMTPResponseException(
                code=451, message="Internal error, try again later"
            )

        success = False
        response_message = ""
        for hostname in smtp_servers:
            try:
                transport = SMTPClient(
                    hostname=hostname, port=25, use_tls=False, loop=self.loop
                )
                await transport.connect()
                self.log.debug("SMTP connection to %s established", hostname)

                # Upgrade TLS encrypted connection
                if transport.supports_extension("starttls"):
                    await transport.starttls()
                    self.log.debug(
                        "SMTP connection %s upgraded using STARTTLS", hostname
                    )

                recipient_errors, response_message = await transport.sendmail(
                    sender=sender, recipients=[rcpt.address], message=msg.to_string()
                )
                success = not recipient_errors
                if not success:
                    self.log.warning(
                        "Failed sending mail for %s: %s (%s)",
                        rcpt.address,
                        recipient_errors,
                        response_message,
                    )
                break
            except (SMTPServerDisconnected, SMTPConnectError, SMTPTimeoutError) as e:
                self.log.warning(
                    "SMTP connection to %s failed for %s",
                    hostname,
                    rcpt.address,
                    exc_info=True,
                )
                continue
            except SMTPException as e:
                self.log.exception("SMTP failure forwarding to %s", rcpt.address)
                break

        if not success:
            raise SMTPResponseException(code=451, message="Error processing message.")

        return response_message

    @cached(TTLCache(maxsize=1024, ttl=900))
    async def _check_dnsbl(self, ip: str) -> bool:
        """
        Helper to check if an IP address is listed in common DNS blacklists.

        Args:
            ip: The client IP address

        Returns:
            True if listed in common DNSBL, False otherwise.
        """
        dnsbl = DNSBLChecker()
        try:
            result: DNSBLResult = await dnsbl._check_ip(addr=ip)
        except ValueError:
            self.log.exception("Error checking DNSBL for %s", ip)
            result = DNSBLResult(addr=ip, results=[])

        self.log.info("DNSBL result for %s: %s", ip, result)
        return result.blacklisted and ip not in ["127.0.0.1", "::1"]

    async def _get_mx_records(self, domain: str) -> List[str]:
        """
        Helper to get the MX records for a domain, sorted by priority.

        Args:
            domain: The domain to look up

        Returns:
            List of mail exchangers sorted by priority.
        """
        resolver = DNSResolver(loop=self.loop)
        return [
            r.host
            for r in sorted(
                await resolver.query(domain, "MX"), key=lambda r: r.priority
            )
        ]

    async def _parse_mailbox(self, rcpt: EmailAddress) -> str:
        """
        Helper to extract the username from a recipient address.

        Args:
            rcpt: An email address from a RCPT TO command.

        Returns:
            The username for this recipient address.
        """
        mailbox = rcpt.mailbox

        if "+" in mailbox:
            mailbox = mailbox.split("+")[0]

        return idna.decode(mailbox).lower()

    async def _parse_filter(self, rcpt: EmailAddress) -> Optional[str]:
        """
        Helper to extract the filter (plussed part) from a recipient address

        Args:
            rcpt: An email address from a RCPT TO command.

        Returns:
            The filter/plussed address part of this email address.
        """
        if "+" not in rcpt.mailbox:
            return None

        return rcpt.mailbox.split("+", maxsplit=2)[1]

    async def _parse_domain(self, rcpt: EmailAddress) -> str:
        """
        Helper to extract the domain from a recipient address

        Args:
            rcpt: An email address from a RCPT TO command.

        Returns:
            The domain part of a recipient address.
        """
        if not rcpt.hostname:
            self.log.debug("%s is not a valid recipient", rcpt.address)
            raise SMTPResponseException(code=550, message=f"{rcpt.address} is invalid")

        domain = FQDN(fqdn=idna.decode(rcpt.hostname))

        if not domain.is_valid:
            self.log.debug("%s is not a FQDN", domain.relative)
            raise SMTPResponseException(
                code=550, message=f"{domain.relative} is not a FQDN"
            )

        if domain.relative in blacklisted_domains:
            self.log.debug("%s is blacklisted", domain.relative)
            raise SMTPResponseException(
                code=550, message=f"{domain.relative} is not permitted"
            )

        if domain.relative in disposable_domains:
            self.log.debug("%s is a disposable email address", domain.relative)
            raise SMTPResponseException(
                code=550, message=f"Disposable email addresses are not permitted"
            )

        return domain.relative

    @cached(TTLCache(maxsize=1024, ttl=300))
    async def _get_forwarding_addresses(self, rcpt: EmailAddress) -> Set[EmailAddress]:
        """
        Get the forwarding addresses for the recipient of the message.

        Args:
            rcpt: The original recipient of the message.

        Returns:
            A set of new recipient addresses
        """
        # TODO: Make this configurable through text records?
        orig_domain = await self._parse_domain(rcpt=rcpt)
        orig_mailbox = await self._parse_mailbox(rcpt=rcpt)
        orig_filter = await self._parse_filter(rcpt=rcpt)

        addresses = self.FORWARDING_ADDRESSES.get(orig_domain)

        global_forwarding_addresses: Set[EmailAddress] = set()
        forwarding_addresses: Set[EmailAddress] = set()

        if not addresses:
            raise SMTPResponseException(code=550, message="Mailbox not available")

        for address in addresses:
            # Check for global forwarding
            if not ":" in address:
                global_forwarding_addresses |= self._parse_destination(dest=address)
            else:
                parts = address.split(":")
                if len(parts) != 2:
                    raise SMTPResponseException(code=451, message="Lookup failure")
                if orig_mailbox == parts[0]:
                    forwarding_addresses |= self._parse_destination(dest=parts[1])
                    break

        if not forwarding_addresses and global_forwarding_addresses:
            forwarding_addresses = global_forwarding_addresses

        if not forwarding_addresses:
            raise SMTPResponseException(code=550, message="Mailbox not available")

        # Transfer the filter part to the new destination address
        if orig_filter is not None:
            forwarding_addresses = {
                addr
                if "+" in addr.mailbox
                else parse_address(f"{addr.mailbox}+{orig_filter}@{addr.hostname}")
                for addr in forwarding_addresses
            }

        self.log.info("Forwarding mail for %s to %s", rcpt, forwarding_addresses)
        return forwarding_addresses

    def _parse_destination(self, dest: str) -> Set[EmailAddress]:
        """
        Helper to parse a forward destination into email addresses.

        Args:
            dest: The destination string from the configuration

        Returns:
            Set of email addresses
        """
        result: Set[EmailAddress] = set()

        for addr in dest.split("|"):
            address = parse_address(addr)
            if address is None:
                continue
            result.add(address)

        return result
