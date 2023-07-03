# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PyghmiCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The '{}' module may transmit data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "pyghmi.ipmi.command.*": [
                    "Command",
                    "Console",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "pyghmi.ipmi.command.Command",
            "pyghmi.ipmi.command.Console",
        ]:
            argument = call.get_argument(position=2, name="password")
            passwd = argument.value

            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.function_node,
                    ),
                    level=Level.ERROR,
                    message=f"The {call.name_qualified} module may "
                    f"transmit the password argument in cleartext.",
                )
            else:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.function_node,
                    ),
                    message=self.message.format(call.name_qualified),
                )
