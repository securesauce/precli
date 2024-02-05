# Copyright 2024 Secure Saurce LLC
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class Assert(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="assert",
            full_descr=__doc__,
            cwe_id=703,
            message="",
            targets=("assert"),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if context["node"].type == "assert":
            return Result(
                rule_id=self.id,
                artifact=context["artifact"],
                location=Location(kwargs.get("func_node")),
            )
