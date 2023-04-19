# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class PycryptodomexWeakHash(Rule):
    def __init__(self):
        super().__init__(
            id="PRE313",
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
                "Cryptodome.Hash.MD2.new",
                "Cryptodome.Hash.MD4.new",
                "Cryptodome.Hash.MD5.new",
                "Cryptodome.Hash.RIPEMD.new",
                "Cryptodome.Hash.RIPEMD160.new",
                "Cryptodome.Hash.SHA.new",
                "Cryptodome.Hash.SHA1.new",
            ],
        ):
            return Result(
                rule_id=self.id,
                context=context,
                level=Level.ERROR,
                message=self.message.format(context["func_call_qual"]),
            )
