# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.location import Location
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
            message="The '{}' protocol has insufficient encryption strength.",
            targets=("call"),
        )

    def analyze(self, context: dict, *args: list, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["ssl.get_server_certificate"]):
            args = context["func_call_args"]
            version = context["func_call_kwargs"].get("ssl_version")

            if len(args) > 1:
                if isinstance(args[1], str) and args[1] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 1)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS_CLIENT' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS_CLIENT",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(version),
                        fixes=fixes,
                    )
            elif version is not None:
                if isinstance(version, str) and version in INSECURE_VERSIONS:
                    node = Rule.get_keyword_arg(context["node"], "ssl_version")
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS_CLIENT' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS_CLIENT",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(version),
                        fixes=fixes,
                    )
        if Rule.match_calls(context, ["ssl.wrap_socket"]):
            args = context["func_call_args"]
            version = context["func_call_kwargs"].get("ssl_version")

            # TODO(ericwb): It's better to recommend PROTOCOL_TLS_CLIENT or
            # PROTOCOL_TLS_SERVER, as PROTOCOL_TLS is deprecated but in order
            # to know whether this is a client or server socket, the
            # server_side argument needs to be checked.

            if len(args) > 5:
                if isinstance(args[5], str) and args[5] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 5)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(version),
                        fixes=fixes,
                    )
            elif version is not None:
                if isinstance(version, str) and version in INSECURE_VERSIONS:
                    node = Rule.get_keyword_arg(context["node"], "ssl_version")
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(version),
                        fixes=fixes,
                    )
        if Rule.match_calls(context, ["ssl.SSLContext"]):
            args = context["func_call_args"]
            protocol = context["func_call_kwargs"].get("protocol")

            if args:
                if isinstance(args[0], str) and args[0] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 0)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(protocol),
                        fixes=fixes,
                    )
            elif protocol is not None:
                if isinstance(protocol, str) and protocol in INSECURE_VERSIONS:
                    node = Rule.get_keyword_arg(context["node"], "protocol")
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content="PROTOCOL_TLS",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(protocol),
                        fixes=fixes,
                    )
