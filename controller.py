#!/usr/bin/env python3
from aiosmtpd.controller import Controller
from smtp import SMTP


class ForwardController(Controller):
    """
    SMTP Controller
    """

    DATA_SIZE_DEFAULT = 25 * 1024 * 1024  # 25MiB

    def factory(self) -> SMTP:
        """
        Customize the handler/server creation.
        """
        return SMTP(
            handler=self.handler,
            data_size_limit=self.DATA_SIZE_DEFAULT,
            enable_SMTPUTF8=self.enable_SMTPUTF8,
        )
