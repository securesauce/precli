# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class FtpCleartext(Rule):
    """
    .. seealso::

     - https://docs.python.org/3/library/ftplib.html
    """

    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The FTP protocol transmits data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "ftplib.*": [
                    "FTP",
                ]
            },
        )

    def analyze(self, context: dict) -> Result:
        """
        FTP(
            host='',
            user='',
            passwd='',
            acct='',
            timeout=<object object at 0x104730630>,
            source_address=None,
            *,
            encoding='utf-8'
        )

        FTP_TLS(
            host='',
            user='',
            passwd='',
            acct='',
            keyfile=None,
            certfile=None,
            context=None,
            timeout=<object object at 0x104730630>,
            source_address=None,
            *,
            encoding='utf-8'
        )
        """
        if (
            call_node := Rule.match_calls(context, ["ftplib.FTP"])
        ) is not None:
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            passwd = args[2] if len(args) > 2 else kwargs.get("passwd", None)

            context["node"] = call_node
            fixes = Rule.get_fixes(
                context=context,
                description="Use the 'FTP_TLS' module to secure the "
                "connection.",
                inserted_content="FTP_TLS",
            )

            # TODO(ericwb): also check for call to FTP().login(user, password)
            # but this could trigger two errors, one for the constructor and
            # one for the login call.

            # Default of context=None creates unsecure
            # _create_unverified_context. Therefore need to suggest
            # create_default_context as part of fix.

            # TODO(ericwb): the fix should also call prot_p() to secure the
            # data connection

            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=f"The '{context['func_call_qual']}' module will "
                    f"transmit the password argument in cleartext.",
                    fixes=fixes,
                )
            else:
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(context["func_call_qual"]),
                    fixes=fixes,
                )
