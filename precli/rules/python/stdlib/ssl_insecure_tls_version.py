# Copyright 2024 Secure Sauce LLC
r"""
# Inadequate Encryption Strength Using Weak SSL Protocols

The Python `ssl` modules provide a number of different protocols that can be
used to encrypt data. However, some of these protocols are no longer
considered secure and should not be used.

The following protocols are considered weak and should not be used:

- `ssl.PROTOCOL_SSLv2`
- `ssl.PROTOCOL_SSLv3`
- `ssl.PROTOCOL_TLSv1`
- `ssl.PROTOCOL_TLSv1_1`

These protocols have a number of known security vulnerabilities that can be
exploited by attackers. For example, the BEAST attack can be used to steal
sensitive data, such as passwords and credit card numbers, from applications
that use SSL version 2.

Here are some additional reasons why you should not use the weak Python ssl
protocols:

- They are not secure. As mentioned above, the weak protocols have a number of
  known security vulnerabilities that can be exploited by attackers.
- They are not recommended by security experts. Security experts recommend
  using the `ssl.PROTOCOL_TLS_SERVER` or `ssl.PROTOCOL_TLS_CLIENT` protocol
  instead.

## Example

```python
import ssl


ssl.get_server_certificate(
    ("localhost", 443), ssl_version=ssl.PROTOCOL_SSLv2
)
```

## Remediation

If you need to connect to a server over HTTPS, you should use the
`ssl.PROTOCOL_TLS_SERVER` or `ssl.PROTOCOL_TLS_CLIENT` protocol instead.
These protocols are more secure than the weak protocols and will help to
protect your application from these security risks.

```python
import ssl


ssl.get_server_certificate(
    ("localhost", 443), ssl_version=ssl.PROTOCOL_TLSv1_2
)
```

## See also

- [ssl — TLS/SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

_New in version 0.1.0_

"""  # noqa: E501
from precli.core.argument import Argument
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


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
            description=__doc__,
            cwe_id=326,
            message="The '{0}' protocol has insufficient encryption strength.",
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified in ["ssl.get_server_certificate"]:
            # get_server_certificate(
            #     addr,
            #     ssl_version=<_SSLMethod.PROTOCOL_TLS_CLIENT: 16>,
            #     ca_certs=None,
            #     timeout=<object object at 0x1007186e0>
            # )
            argument = call.get_argument(position=1, name="ssl_version")
            version = argument.value

            if isinstance(version, str) and version in INSECURE_VERSIONS:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use 'PROTOCOL_TLS_CLIENT' to "
                    "auto-negotiate the highest protocol version that "
                    "both the client and server support.",
                    inserted_content="PROTOCOL_TLS_CLIENT",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.identifier_node),
                    message=self.message.format(version),
                    fixes=fixes,
                )
        if call.name_qualified in ["ssl.wrap_socket"]:
            # wrap_socket(
            #     sock,
            #     keyfile=None,
            #     certfile=None,
            #     server_side=False,
            #     cert_reqs=<VerifyMode.CERT_NONE: 0>,
            #     ssl_version=<_SSLMethod.PROTOCOL_TLS: 2>,
            #     ca_certs=None,
            #     do_handshake_on_connect=True,
            #     suppress_ragged_eofs=True,
            #     ciphers=None
            # )
            argument = call.get_argument(position=1, name="ssl_version")
            version = argument.value
            server_side = call.get_argument(
                position=3, name="server_side", default=Argument(None, False)
            ).value
            content = (
                "PROTOCOL_TLS_SERVER" if server_side else "PROTOCOL_TLS_CLIENT"
            )

            if isinstance(version, str) and version in INSECURE_VERSIONS:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use 'PROTOCOL_TLS' to "
                    "auto-negotiate the highest protocol version that "
                    "both the client and server support.",
                    inserted_content=content,
                )
                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.identifier_node),
                    message=self.message.format(version),
                    fixes=fixes,
                )
        if call.name_qualified in ["ssl.SSLContext"]:
            # SSLContext(protocol=None, *args, **kwargs)
            argument = call.get_argument(position=0, name="protocol")
            protocol = argument.value

            if isinstance(protocol, str) and protocol in INSECURE_VERSIONS:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use 'PROTOCOL_TLS' to "
                    "auto-negotiate the highest protocol version that "
                    "both the client and server support.",
                    inserted_content="PROTOCOL_TLS",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.identifier_node),
                    message=self.message.format(protocol),
                    fixes=fixes,
                )
