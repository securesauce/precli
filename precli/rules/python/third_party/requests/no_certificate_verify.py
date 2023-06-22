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
                "requests.*": [
                    "delete",
                    "get",
                    "head",
                    "options",
                    "patch",
                    "post",
                    "put",
                    "request",
                    "Session",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "requests.delete",
            "requests.get",
            "requests.head",
            "requests.options",
            "requests.patch",
            "requests.post",
            "requests.put",
            "requests.request",
            "requests.Session.delete",
            "requests.Session.get",
            "requests.Session.head",
            "requests.Session.options",
            "requests.Session.patch",
            "requests.Session.post",
            "requests.Session.put",
            "requests.Session.request",
        ]:
            argument = call.get_argument(name="verify")
            verify = argument.value

            if verify is False:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Set the 'verify' argument to 'True' to ensure"
                    " the server's certificate is verified.",
                    inserted_content="True",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
