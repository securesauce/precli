# Copyright 2023 Secure Saurce LLC
from precli.core.config import Configuration
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class YamlLoad(Rule):
    def __init__(self):
        super().__init__(
            id="PRE1010",
            name="yaml_load",
            short_descr="",
            full_descr="",
            help_url="",
            configuration=Configuration(),
            cwe=20,
            message="",
        )

    def analyze(self, context: dict) -> Result:
        if all(
            [
                Rule.match_calls(context, [b"yaml.load"]),
                not Rule.match_call_kwarg(
                    context, b"Loader", b"yaml.SafeLoader"
                ),
                not Rule.match_call_kwarg(
                    context, b"Loader", b"yaml.CSafeLoader"
                ),
                not Rule.match_call_arg_pos(context, 1, b"yaml.SafeLoader"),
                not Rule.match_call_arg_pos(context, 1, b"yaml.CSafeLoader"),
            ]
        ):
            return Result(
                id="PRE1010",
                level=Level.WARNING,
                message="",
            )
