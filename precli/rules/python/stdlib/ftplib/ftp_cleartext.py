# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.location import Location
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

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["ftplib.FTP"]):
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
            call_args = kwargs["func_call_args"]
            call_kwargs = kwargs["func_call_kwargs"]
            passwd = (
                call_args[2]
                if len(call_args) > 2
                else call_kwargs.get("passwd", None)
            )

            node = Rule.get_func_ident(kwargs.get("func_node"))
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=node),
                description="Use the 'FTP_TLS' module to secure the "
                "connection.",
                inserted_content="FTP_TLS",
            )

            # TODO(ericwb): Default of FTP_TLS context=None creates unsecure
            # _create_unverified_context. Therefore need to suggest
            # create_default_context as part of fix.

            # TODO(ericwb): the fix should also call prot_p() to secure the
            # data connection

            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    level=Level.ERROR,
                    message=f"The '{context['func_call_qual']}' module will "
                    f"transmit the password argument in cleartext.",
                    fixes=fixes,
                )
            else:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    message=self.message.format(context["func_call_qual"]),
                    fixes=fixes,
                )
        if Rule.match_calls(context, ["ftplib.FTP.login"]):
            """
            login(self, user='', passwd='', acct='')
            """
            call_args = kwargs["func_call_args"]
            call_kwargs = kwargs["func_call_kwargs"]
            passwd = (
                call_args[1]
                if len(call_args) > 1
                else call_kwargs.get("passwd", None)
            )

            node = Rule.get_func_ident(kwargs.get("func_node"))
            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(context["file_name"], node),
                    level=Level.ERROR,
                    message=f"The '{context['func_call_qual']}' function will "
                    f"transmit the password argument in cleartext.",
                )
