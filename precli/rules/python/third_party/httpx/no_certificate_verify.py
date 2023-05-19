# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class NoCertificateVerify(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The {} function is set to not verify certificates.",
            targets=("call"),
            wildcards={
                "httpx.*": [
                    "AsyncClient",
                    "Client",
                    "delete",
                    "get",
                    "head",
                    "options",
                    "patch",
                    "post",
                    "put",
                    "request",
                    "stream",
                ]
            },
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(
            context,
            [
                "httpx.AsyncClient",
                "httpx.Client",
                "httpx.delete",
                "httpx.get",
                "httpx.head",
                "httpx.options",
                "httpx.patch",
                "httpx.post",
                "httpx.put",
                "httpx.request",
                "httpx.stream",
            ],
        ):
            if (
                node := Rule.match_call_kwarg(context, "verify", [False])
            ) is not None:
                context["node"] = node
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(context["func_call_qual"]),
                )
