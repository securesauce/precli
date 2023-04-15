# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.result import Result
from precli.core.rule import Rule


class PandasReadPickle(Rule):
    def __init__(self):
        super().__init__(
            id="PRE310",
            name="deserialization_of_untrusted_data",
            short_descr="The application deserializes untrusted data without "
            "sufficiently verifying that the resulting data will be valid.",
            full_descr=__doc__,
            help_url="",
            config=Config(),
            cwe=502,
            message="Potential unsafe usage of {} that can allow "
            "instantiation of arbitrary objects.",
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, [b"pandas.read_pickle"]):
            return Result(
                rule_id=self.id,
                file_name=context["file_name"],
                start_point=context["node"].start_point,
                end_point=context["node"].end_point,
                message=self.message.format(context["func_call_qual"]),
            )
