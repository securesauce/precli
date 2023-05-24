# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


WEAK_HASHES = ("md4", "md5", "ripemd160", "sha", "sha1")


class HashlibWeakHash(Rule):
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
                "hashlib.*": [
                    "md4",
                    "md5",
                    "ripemd160",
                    "sha",
                    "sha1",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(
            context,
            [
                "hashlib.md4",
                "hashlib.md5",
                "hashlib.ripemd160",
                "hashlib.sha",
                "hashlib.sha1",
            ],
        ):
            kwargs = context["func_call_kwargs"]
            if kwargs.get("usedforsecurity", True) is True:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    level=Level.ERROR,
                    message=self.message.format(kwargs.get("func_call_qual")),
                )
        elif Rule.match_calls(context, ["hashlib.new"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            name = args[0] if args else kwargs.get("name", None)

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                if kwargs.get("usedforsecurity", True) is True:
                    return Result(
                        rule_id=self.id,
                        location=Location(
                            context["file_name"], kwargs.get("func_node")
                        ),
                        level=Level.ERROR,
                        message=self.message.format(name),
                    )
