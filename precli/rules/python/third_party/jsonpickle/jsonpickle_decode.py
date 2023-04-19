# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


class JsonpickleDecode(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe=502,
            message="Potential unsafe usage of {} that can allow "
            "instantiation of arbitrary objects.",
        )

    def analyze(self, context: dict) -> Result:
        if any(
            [
                Rule.match_calls(context, ["jsonpickle.decode"]),
                Rule.match_calls(context, ["jsonpickle.unpickler.decode"]),
                Rule.match_calls(context, ["jsonpickle.unpickler.Unpickler"]),
            ]
        ):
            return Result(
                rule_id=self.id,
                context=context,
                message=self.message.format(context["func_call_qual"]),
            )
