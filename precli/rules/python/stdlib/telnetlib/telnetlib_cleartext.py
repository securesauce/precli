# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class TelnetlibCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The '{}' module transmits data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "telnetlib.*": [
                    "Telnet",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["telnetlib.Telnet"]):
            return Result(
                rule_id=self.id,
                location=Location(
                    context["file_name"], kwargs.get("func_node")
                ),
                level=Level.ERROR,
                message=self.message.format(kwargs.get("func_call_qual")),
            )
