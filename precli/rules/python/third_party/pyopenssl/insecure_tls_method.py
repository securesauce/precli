# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


INSECURE_METHODS = (
    "OpenSSL.SSL.SSLv2_METHOD",
    "OpenSSL.SSL.SSLv3_METHOD",
    "OpenSSL.SSL.TLSv1_METHOD",
    "OpenSSL.SSL.TLSv1_1_METHOD",
)


class InsecureTlsMethod(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            full_descr=__doc__,
            cwe_id=326,
            message="The '{}' method has insufficient encryption strength.",
            targets=("call"),
            wildcards={
                "OpenSSL.SSL.*": [
                    "Context",
                    "SSLv2_METHOD",
                    "SSLv3_METHOD",
                    "TLSv1_METHOD",
                    "TLSv1_1_METHOD",
                ],
                "OpenSSL.*": [
                    "SSL.Context",
                    "SSL.SSLv2_METHOD",
                    "SSL.SSLv3_METHOD",
                    "SSL.TLSv1_METHOD",
                    "SSL.TLSv1_1_METHOD",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["OpenSSL.SSL.Context"]:
            argument = call.get_argument(position=1, name="method")
            method = argument.value

            if isinstance(method, str) and method in INSECURE_METHODS:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use 'TLS_METHOD' to auto-negotiate the "
                    "highest protocol version that both the client and "
                    "server support.",
                    inserted_content="TLS_METHOD",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format(method),
                    fixes=fixes,
                )
