#!/usr/bin/env python3
import asyncio
import logging

import click

from controller import ForwardController
from handler import ForwardHandler


async def _server(hostname: str = "*", port: int = 25) -> None:
    controller = ForwardController(
        hostname=hostname, port=port, handler=ForwardHandler()
    )
    controller.start()


@click.command()
@click.option(
    "--hostname", default="*", type=str, help="The hostname/IP address to listen on"
)
@click.option("--port", default=25, type=int, help="The TCP port to listen on")
def server(hostname: str = "::1", port: int = 25) -> None:
    """
    Main entry point into the SMTP forwarder
    Args:
        hostname: The hostname/IP to listen on
        port: The TCP port to listen on
        tls: Support/require TLS encryption

    Returns:
        Nothing
    """
    logging.basicConfig(level=logging.DEBUG)
    loop = asyncio.get_event_loop()
    loop.create_task(_server(hostname=hostname, port=port))

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    server()
