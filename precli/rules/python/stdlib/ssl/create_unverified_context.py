# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class CreateUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The {} function does not properly validate certificates.",
            targets=("call"),
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["ssl._create_unverified_context"]):
            return Result(
                rule_id=self.id,
                context=context,
                level=Level.ERROR,
                message=self.message.format(context["func_call_qual"]),
            )
