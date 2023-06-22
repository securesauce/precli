# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class JsonpickleDecode(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe_id=502,
            message="Potential unsafe usage of '{}' that can allow "
            "instantiation of arbitrary objects.",
            targets=("call"),
            wildcards={
                "jsonpickle.*": [
                    "decode",
                ],
                "jsonpickle.unpickler.*": [
                    "decode",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "jsonpickle.decode",
            "jsonpickle.unpickler.decode",
            "jsonpickle.Unpickler.Unpickler",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                message=self.message.format(call.name_qualified),
            )
