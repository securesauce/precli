# Copyright 2024 Secure Sauce LLC
r"""
# Binding to an Unrestricted IP Address in `socket` Module

Sockets can be bound to the IPv4 address `0.0.0.0` or IPv6 equivalent of
`::`, which configures the socket to listen for incoming connections on all
network interfaces. While this can be intended in environments where
services are meant to be publicly accessible, it can also introduce significant
security risks if the service is not intended for public or wide network
access.

Binding a socket to `0.0.0.0` or `::` can unintentionally expose the
application to the wider network or the internet, making it accessible from
any interface. This exposure can lead to unauthorized access, data breaches,
or exploitation of vulnerabilities within the application if the service is
not adequately secured or if the binding is unintended. Restricting the socket
to listen on specific interfaces limits the exposure and reduces the attack
surface.

## Example

```python
import socket


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 8080))
s.listen()
```

## Remediation

All socket bindings MUST specify a specific network interface or localhost
(127.0.0.1/localhost for IPv4, ::1 for IPv6) unless the application is
explicitly designed to be accessible from any network interface. This
practice ensures that services are not exposed more broadly than intended.

```python
import socket


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 8080))
s.listen()
```

## See also

- [socket.create_server — Low-level networking interface](https://docs.python.org/3/library/socket.html#socket.create_server)
- [socket.socket.bind — Low-level networking interface](https://docs.python.org/3/library/socket.html#socket.socket.bind)
- [CWE-1327: Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core import utils
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


INADDR_ANY = "0.0.0.0"
IN6ADDR_ANY = "::"


class SocketUnrestrictedBind(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unrestricted_bind",
            description=__doc__,
            cwe_id=1327,
            message="Binding to '{0}' exposes the application on all network "
            "interfaces, increasing the risk of unauthorized access.",
            wildcards={
                "socket.*": [
                    "create_server",
                    "socket",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in [
            "socket.create_server",
            "socket.socket.bind",
        ]:
            return

        arg = call.get_argument(position=0, name="address")
        address = arg.value

        if not isinstance(address, tuple):
            return

        if utils.to_str(address[0]) in ("", INADDR_ANY):
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description="Use the localhost address to restrict binding.",
                inserted_content=str(("127.0.0.1",) + address[1:]),
            )
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format("INADDR_ANY (0.0.0.0)"),
                fixes=fixes,
            )
        if utils.to_str(address[0]) == IN6ADDR_ANY:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description="Use the localhost address to restrict binding.",
                inserted_content=str(("::1",) + address[1:]),
            )
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format("IN6ADDR_ANY (::)"),
                fixes=fixes,
            )
