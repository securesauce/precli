# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class FtplibCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The {} module transmits data in cleartext without "
            "encryption.",
            targets=("call"),
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["ftplib.FTP"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            passwd = args[2] if len(args) > 2 else kwargs.get("passwd", None)

            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=f"The {context['func_call_qual']} module will "
                    f"transmit the password argument in cleartext.",
                )
            else:
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(context["func_call_qual"]),
                )
