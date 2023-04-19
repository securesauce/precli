# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class CryptographyWeakHash(Rule):
    def __init__(self):
        super().__init__(
            id="PRE301",
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe=328,
            message="Use of weak hash function {} does not meet security "
            "expectations.",
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(
            context,
            [
                "cryptography.hazmat.primitives.hashes.MD5",
                "cryptography.hazmat.primitives.hashes.SHA1",
            ],
        ):
            return Result(
                rule_id=self.id,
                context=context,
                level=Level.ERROR,
                message=self.message.format(context["func_call_qual"]),
            )
