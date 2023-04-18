# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


class YamlLoad(Rule):
    def __init__(self):
        super().__init__(
            id="PRE317",
            name="deserialization_of_untrusted_data",
            short_descr="The application deserializes untrusted data without "
            "sufficiently verifying that the resulting data will be valid.",
            full_descr=__doc__,
            cwe=502,
            message="Potential unsafe usage of {} that can allow "
            "instantiation of arbitrary objects.",
        )

    def analyze(self, context: dict) -> Result:
        if all(
            [
                Rule.match_calls(context, ["yaml.load"]),
                not Rule.match_call_kwarg(
                    context, "Loader", "yaml.SafeLoader"
                ),
                not Rule.match_call_kwarg(
                    context, "Loader", "yaml.CSafeLoader"
                ),
                not Rule.match_call_pos_arg(context, 1, "yaml.SafeLoader"),
                not Rule.match_call_pos_arg(context, 1, "yaml.CSafeLoader"),
            ]
        ):
            return Result(
                rule_id=self.id,
                context=context,
                message=self.message.format(context["func_call_qual"]),
            )
