# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


INSECURE_VERSIONS = (
    "ssl.PROTOCOL_SSLv2",
    "ssl.PROTOCOL_SSLv3",
    "ssl.PROTOCOL_TLSv1",
    "ssl.PROTOCOL_TLSv1_1",
)


class InsecureTlsVersion(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            full_descr=__doc__,
            cwe_id=326,
            message="The {} protocol has insufficient encryption strength.",
            targets=("call"),
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(context, ["ssl.get_server_certificate"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            version = args[1] if len(args) > 1 else kwargs.get("ssl_version")

            if isinstance(version, str) and version in INSECURE_VERSIONS:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(version),
                )
        if Rule.match_calls(context, ["ssl.wrap_socket"]):
            args = context["func_call_args"]
            kwargs = context["func_call_kwargs"]
            version = args[5] if len(args) > 5 else kwargs.get("ssl_version")

            if isinstance(version, str) and version in INSECURE_VERSIONS:
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format(version),
                )
