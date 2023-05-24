# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class CryptographyWeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe_id=328,
            message="Use of weak hash function '{}' does not meet security "
            "expectations.",
            targets=("call"),
            wildcards={
                "cryptography.hazmat.primitives.hashes.*": [
                    "MD5",
                    "SHA1",
                ],
                "cryptography.hazmat.primitives.*": [
                    "hashes.MD5",
                    "hashes.SHA1",
                ],
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(
            context,
            [
                "cryptography.hazmat.primitives.hashes.MD5",
                "cryptography.hazmat.primitives.hashes.SHA1",
            ],
        ):
            return Result(
                rule_id=self.id,
                location=Location(
                    context["file_name"], kwargs.get("func_node")
                ),
                level=Level.ERROR,
                message=self.message.format(kwargs.get("func_call_qual")),
            )
