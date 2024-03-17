# Copyright 2024 Secure Saurce LLC
r"""
# Binding to an Unrestricted IP Address in `socketserver` Module

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
import socketserver


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        socket.sendto(data.upper(), self.client_address)


HOST, PORT = "0.0.0.0", 9999
with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
    server.serve_forever()
```

## Remediation

All socket bindings MUST specify a specific network interface or localhost
(127.0.0.1/localhost for IPv4, ::1 for IPv6) unless the application is
explicitly designed to be accessible from any network interface. This
practice ensures that services are not exposed more broadly than intended.

```python
import socketserver


class MyUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]
        socket.sendto(data.upper(), self.client_address)


HOST, PORT = "127.0.0.1", 9999
with socketserver.UDPServer((HOST, PORT), MyUDPHandler) as server:
    server.serve_forever()
```

## See also

- [socketserver.TCPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.TCPServer)
- [socketserver.UDPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.UDPServer)
- [socketserver.ForkingTCPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.ForkingTCPServer)
- [socketserver.ForkingUDPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.ForkingUDPServer)
- [socketserver.ThreadingTCPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.ThreadingTCPServer)
- [socketserver.ThreadingUDPServer — A framework for network servers](https://docs.python.org/3/library/socketserver.html#socketserver.ThreadingUDPServer)
- [CWE-1327: Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


INADDR_ANY = "0.0.0.0"
IN6ADDR_ANY = "::"


class SocketserverUnrestrictedBind(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unrestricted_bind",
            description=__doc__,
            cwe_id=1327,
            message="Binding to '{0}' exposes the application on all network "
            "interfaces, increasing the risk of unauthorized access.",
            targets=("call"),
            wildcards={
                "socketserver.*": [
                    "TCPServer",
                    "UDPServer",
                    "ForkingTCPServer",
                    "ForkingUDPServer",
                    "ThreadingTCPServer",
                    "ThreadingUDPServer",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")
        if call.name_qualified not in [
            "socketserver.TCPServer",
            "socketserver.UDPServer",
            "socketserver.ForkingTCPServer",
            "socketserver.ForkingUDPServer",
            "socketserver.ThreadingTCPServer",
            "socketserver.ThreadingUDPServer",
        ]:
            return

        arg = call.get_argument(position=0, name="server_address")
        server_address = arg.value

        if isinstance(server_address, tuple) and server_address[0] in (
            "",
            INADDR_ANY,
            IN6ADDR_ANY,
        ):
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format(
                    "INADDR_ANY (0.0.0.0) or IN6ADDR_ANY (::)"
                ),
            )
