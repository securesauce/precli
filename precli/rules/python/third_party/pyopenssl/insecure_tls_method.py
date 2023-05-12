# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
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
            message="The {} method has insufficient encryption strength.",
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
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["OpenSSL.SSL.Context"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            version = args[0] if args else kwargs.get("method")

            if isinstance(version, str) and version in INSECURE_METHODS:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(version),
                )
