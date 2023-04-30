# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


WEAK_CRYPT_HASHES = (
    "crypt.METHOD_CRYPT",
    "crypt.METHOD_MD5",
    "crypt.METHOD_BLOWFISH",
)


class CryptWeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe_id=328,
            message="Use of weak hash function {} does not meet security "
            "expectations.",
            targets=("call"),
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["crypt.crypt"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            name = args[1] if len(args) > 1 else kwargs.get("salt", None)
            if isinstance(name, str) and name in WEAK_CRYPT_HASHES:
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(name),
                )
        elif Rule.match_calls(context, ["crypt.mksalt"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            name = args[0] if args else kwargs.get("method", None)
            if isinstance(name, str) and name in WEAK_CRYPT_HASHES:
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(name),
                )
