# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


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
        if Rule.match_calls(context, ["OpenSSL.SSL.Context"]):
            args = context["func_call_args"]
            method = context["func_call_kwargs"].get("method")

            if method is not None:
                if isinstance(method, str) and method in INSECURE_METHODS:
                    node = Rule.get_keyword_arg(context["node"], "method")
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'TLS_METHOD' to auto-negotiate the "
                        "highest protocol version that both the client and "
                        "server support.",
                        inserted_content="TLS_METHOD",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(method),
                        fixes=fixes,
                    )
            elif args:
                if isinstance(args[0], str) and args[0] in INSECURE_METHODS:
                    node = Rule.get_positional_arg(context["node"], 0)
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'TLS_METHOD' to auto-negotiate the "
                        "highest protocol version that both the client and "
                        "server support.",
                        inserted_content="TLS_METHOD",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(args[0]),
                        fixes=fixes,
                    )
