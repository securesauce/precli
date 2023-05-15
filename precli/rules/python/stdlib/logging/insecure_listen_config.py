# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


class InsecureListenConfig(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="code_injection",
            full_descr=__doc__,
            cwe_id=94,
            message="Using {} with unset verify vulnerable to code injection.",
            targets=("call"),
            wildcards={
                "logging.config.*": [
                    "listen",
                ]
            },
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["logging.config.listen"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]

            print(kwargs)

            verify = args[1] if len(args) > 1 else kwargs.get("verify", None)

            if verify is None:
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(context["func_call_qual"]),
                )
