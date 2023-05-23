# Copyright 2023 Secure Saurce LLC
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class InsecureListenConfig(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="code_injection",
            full_descr=__doc__,
            cwe_id=94,
            message="Using '{}' with unset 'verify' vulnerable to code "
            "injection.",
            targets=("call"),
            wildcards={
                "logging.config.*": [
                    "listen",
                ]
            },
        )

    def analyze(self, context: dict, *args: list, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["logging.config.listen"]):
            call_args = context["func_call_args"]
            call_kwargs = context["func_call_kwargs"]
            verify = (
                call_args[1]
                if len(call_args) > 1
                else call_kwargs.get("verify", None)
            )

            if verify is None:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    message=self.message.format(context["func_call_qual"]),
                )
