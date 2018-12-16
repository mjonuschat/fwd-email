#!/usr/bin/env python3
from asyncio.events import AbstractEventLoop
from typing import Optional

from aiosmtpd import smtp


class SMTP(smtp.SMTP):
    def __init__(
        self,
        *,
        handler: object,
        data_size_limit: int = smtp.DATA_SIZE_DEFAULT,
        enable_SMTPUTF8: bool = False,
        decode_data: bool = False,
        hostname: Optional[str] = None,
        ident: Optional[str] = None,
        tls_context=None,
        require_starttls: bool = False,
        timeout: int = 300,
        loop: Optional[AbstractEventLoop] = None
    ) -> None:
        """
        Initializer.

        Args:
            handler: The handler implementation
            data_size_limit: Maximum message size
            enable_SMTPUTF8: Enable UTF8 SMTP extension
            decode_data: Decode data on receive
            hostname: The hostname of the Server
            ident: Ident string
            tls_context: TLS context to use
            require_starttls: Force STARTTLS command
            timeout: Default connection timeout
            loop: The asyncio event loop to use
        """
        super(SMTP, self).__init__(
            handler=handler,
            data_size_limit=data_size_limit,
            enable_SMTPUTF8=enable_SMTPUTF8,
            decode_data=decode_data,
            hostname=hostname,
            ident=ident,
            tls_context=tls_context,
            require_starttls=require_starttls,
            timeout=timeout,
            loop=loop,
        )
        if loop is not None and self.event_handler:
            self.event_handler.loop = loop
