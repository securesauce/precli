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

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["ssl.get_server_certificate"]):
            """
            get_server_certificate(
                addr,
                ssl_version=<_SSLMethod.PROTOCOL_TLS_CLIENT: 16>,
                ca_certs=None,
                timeout=<object object at 0x1007186e0>
            )
            """
            args = kwargs["func_call_args"]
            version = kwargs["func_call_kwargs"].get("ssl_version")

            if len(args) > 1:
                if isinstance(args[1], str) and args[1] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 1)
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
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
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
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
            """
            wrap_socket(
                sock,
                keyfile=None,
                certfile=None,
                server_side=False,
                cert_reqs=<VerifyMode.CERT_NONE: 0>,
                ssl_version=<_SSLMethod.PROTOCOL_TLS: 2>,
                ca_certs=None,
                do_handshake_on_connect=True,
                suppress_ragged_eofs=True,
                ciphers=None
            )
            """
            args = kwargs["func_call_args"]
            version = kwargs["func_call_kwargs"].get("ssl_version")
            server_side = (
                args[3]
                if len(args) > 3
                else kwargs["func_call_kwargs"].get("server_side", False)
            )
            content = (
                "PROTOCOL_TLS_SERVER" if server_side else "PROTOCOL_TLS_CLIENT"
            )

            if len(args) > 5:
                if isinstance(args[5], str) and args[5] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 5)
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content=content,
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
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'PROTOCOL_TLS' to "
                        "auto-negotiate the highest protocol version that "
                        "both the client and server support.",
                        inserted_content=content,
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        level=Level.ERROR,
                        message=self.message.format(version),
                        fixes=fixes,
                    )
        if Rule.match_calls(context, ["ssl.SSLContext"]):
            """
            SSLContext(
                protocol=None,
                *args,
                **kwargs
            )
            """
            args = kwargs["func_call_args"]
            protocol = kwargs["func_call_kwargs"].get("protocol")

            if args:
                if isinstance(args[0], str) and args[0] in INSECURE_VERSIONS:
                    node = Rule.get_positional_arg(context["node"], 0)
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
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
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
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
