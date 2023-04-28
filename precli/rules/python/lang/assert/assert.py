# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


class Assert(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="assert",
            full_descr=__doc__,
            cwe=703,
            message="",
            targets=("assert"),
        )

    def analyze(self, context: dict) -> Result:
        if context["node"].type == "assert":
            return Result(
                rule_id=self.id,
                context=context,
            )
