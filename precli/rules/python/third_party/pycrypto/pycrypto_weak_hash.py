# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PycryptoWeakHash(Rule):
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
                "Crypto.*": [
                    "Hash.MD2.new",
                    "Hash.MD4.new",
                    "Hash.MD5.new",
                    "Hash.RIPEMD.new",
                    "Hash.SHA.new",
                ],
                "Crypto.Hash.*": [
                    "MD2.new",
                    "MD4.new",
                    "MD5.new",
                    "RIPEMD.new",
                    "SHA.new",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "Crypto.Hash.MD2.new",
            "Crypto.Hash.MD4.new",
            "Crypto.Hash.MD5.new",
            "Crypto.Hash.RIPEMD.new",
            "Crypto.Hash.SHA.new",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
            )
