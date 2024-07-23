# Copyright 2024 Secure Sauce LLC
r"""
# Binding to an Unrestricted IP Address in `xmlrpc.server` Module

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

# Example

```python linenums="1" hl_lines="5 6" title="xmlrpc_server_doc_xml_rpc_server.py"
from xmlrpc.server import DocXMLRPCServer


def run(server_class: DocXMLRPCServer):
    server_address = ("::", 8000)
    httpd = server_class(server_address, allow_none=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run(DocXMLRPCServer)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/xmlrpc/examples/xmlrpc_server_doc_xml_rpc_server.py
    ⚠️  Warning on line 6 in tests/unit/rules/python/stdlib/xmlrpc/examples/xmlrpc_server_doc_xml_rpc_server.py
    PY032: Binding to an Unrestricted IP Address
    Binding to 'IN6ADDR_ANY (::)' exposes the application on all network interfaces, increasing the risk of unauthorized access.
    ```

# Remediation

All socket bindings MUST specify a specific network interface or localhost
(127.0.0.1/localhost for IPv4, ::1 for IPv6) unless the application is
explicitly designed to be accessible from any network interface. This
practice ensures that services are not exposed more broadly than intended.

```python linenums="1"  hl_lines="5" title="xmlrpc_server_doc_xml_rpc_server.py"
from xmlrpc.server import DocXMLRPCServer


def run(server_class: DocXMLRPCServer):
    server_address = ("127.0.0.1", 8000)
    httpd = server_class(server_address, allow_none=True)
    httpd.serve_forever()


if __name__ == "__main__":
    run(DocXMLRPCServer)
```

# See also

!!! info
    - [xmlrpc.server.DocXMLRPCServer — Basic XML-RPC servers](https://docs.python.org/3/library/xmlrpc.server.html#xmlrpc.server.DocXMLRPCServer)
    - [xmlrpc.server.SimpleXMLRPCServer — HTTP servers](https://docs.python.org/3/library/xmlrpc.server.html#xmlrpc.server.SimpleXMLRPCServer)
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


class XmlrpcServerUnrestrictedBind(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unrestricted_bind",
            description=__doc__,
            cwe_id=1327,
            message="Binding to '{0}' exposes the application on all network "
            "interfaces, increasing the risk of unauthorized access.",
            wildcards={
                "xmlrpc.server.*": [
                    "DocXMLRPCServer",
                    "SimpleXMLRPCServer",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "xmlrpc.server.DocXMLRPCServer",
            "xmlrpc.server.SimpleXMLRPCServer",
        ]:
            return

        arg = call.get_argument(position=0, name="addr")
        addr = arg.value

        if not isinstance(addr, tuple):
            return

        if utils.to_str(addr[0]) in ("", INADDR_ANY):
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description="Use the localhost address to restrict binding.",
                inserted_content=str(("127.0.0.1",) + addr[1:]),
            )
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format("INADDR_ANY (0.0.0.0)"),
                fixes=fixes,
            )
        if utils.to_str(addr[0]) == IN6ADDR_ANY:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description="Use the localhost address to restrict binding.",
                inserted_content=str(("::1",) + addr[1:]),
            )
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format("IN6ADDR_ANY (::)"),
                fixes=fixes,
            )
