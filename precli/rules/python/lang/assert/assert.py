# Copyright 2023 Secure Saurce LLC
from precli.core.base_rule import Rule
from precli.core.config import Configuration
from precli.core.result import Result


class Assert(Rule):

    def __init__(self):
        super().__init__(
            id="PRE1001",
            name="assert",
            short_descr="",
            full_descr="",
            help_url="",
            configuration=Configuration(),
            cwe=703,
            message="",
        )

    def analyze(self, context: dict) -> Result:
        if context["node"].type == "assert":
            result = Result(
                self.id,
                self.defaultConfiguration.level,
                self.message,
            )
            return result

