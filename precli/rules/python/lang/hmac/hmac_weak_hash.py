# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


WEAK_HASHES = ("md4", "md5", "ripemd160", "sha", "sha1")


class HmacWeakHash(Rule):
    def __init__(self):
        super().__init__(
            id="PRE008",
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe=328,
            message="Use of weak hash function {} does not meet security "
            "expectations.",
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["hmac.new"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            name = args[2] if len(args) > 2 else kwargs.get("digestmod", None)

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(name),
                )
        elif Rule.match_calls(context, ["hmac.digest"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            name = args[2] if len(args) > 2 else kwargs.get("digest", None)

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(name),
                )
