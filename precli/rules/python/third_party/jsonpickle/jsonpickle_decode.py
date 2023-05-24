# Copyright 2023 Secure Saurce LLC
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
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(
            context,
            [
                "jsonpickle.decode",
                "jsonpickle.unpickler.decode",
                "jsonpickle.Unpickler.Unpickler",
            ],
        ):
            return Result(
                rule_id=self.id,
                location=Location(
                    context["file_name"], kwargs.get("func_node")
                ),
                message=self.message.format(kwargs.get("func_call_qual")),
            )
