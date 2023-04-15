# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.result import Result
from precli.core.rule import Rule


class Assert(Rule):
    def __init__(self):
        super().__init__(
            id="PRE1001",
            name="assert",
            short_descr="",
            full_descr="",
            help_url="",
            config=Config(),
            cwe=703,
            message="",
        )

    def analyze(self, context: dict) -> Result:
        if context["node"].type == "assert":
            return Result(
                rule_id=self.id,
                file_name=context["file_name"],
                start_point=context["node"].start_point,
                end_point=context["node"].end_point,
            )
