# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class NoCertificateVerify(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' function is set to not verify certificates.",
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
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
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
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=node),
                    description="Set the 'verify' argument to 'True' to ensure"
                    " the server's certificate is verified.",
                    inserted_content="True",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(context["file_name"], node),
                    level=Level.ERROR,
                    message=self.message.format(kwargs.get("func_call_qual")),
                    fixes=fixes,
                )
