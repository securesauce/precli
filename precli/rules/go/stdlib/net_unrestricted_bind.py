# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
r"""
# Binding to an Unrestricted IP Address in `net` Package

Sockets can be bound to the IPv4 address `0.0.0.0` or IPv6 equivalent of
`[::]`, which configures the socket to listen for incoming connections on all
network interfaces. While this can be intended in environments where
services are meant to be publicly accessible, it can also introduce significant
security risks if the service is not intended for public or wide network
access.

Binding a socket to `0.0.0.0` or `[::]` can unintentionally expose the
application to the wider network or the internet, making it accessible from
any interface. This exposure can lead to unauthorized access, data breaches,
or exploitation of vulnerabilities within the application if the service is
not adequately secured or if the binding is unintended. Restricting the socket
to listen on specific interfaces limits the exposure and reduces the attack
surface.

# Example

```go linenums="1" hl_lines="9" title="net_listen_ipv4.go"
package main

import (
    "log"
    "net"
)

func main() {
    ln, err := net.Listen("tcp", "0.0.0.0:8443")
    if err != nil {
        log.Fatalf("net.Listen failed on %s: %v", "0.0.0.0", err)
    }
    defer ln.Close()
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/go/stdlib/net/examples/net_listen_ipv4.go
    ⚠️  Warning on line 14 in tests/unit/rules/go/stdlib/net/examples/net_listen_ipv4.go
    GO005: Binding to an Unrestricted IP Address
    Binding to 'INADDR_ANY (0.0.0.0)' exposes the application on all network interfaces, increasing the risk of unauthorized access.
    ```

# Remediation

All socket bindings MUST specify a specific network interface or localhost
(127.0.0.1/localhost for IPv4, [::1] for IPv6) unless the application is
explicitly designed to be accessible from any network interface. This
practice ensures that services are not exposed more broadly than intended.

```go linenums="1" hl_lines="9" title="net_listen_ipv4.go"
package main

import (
    "log"
    "net"
)

func main() {
    ln, err := net.Listen("tcp", "0.0.0.0:8443")
    if err != nil {
        log.Fatalf("net.Listen failed on %s: %v", "0.0.0.0", err)
    }
    defer ln.Close()
}
```

# Default Configuration

```toml
enabled = true
level = "warning"
```

# See also

!!! info
    - [net package - net - Go Packages](https://pkg.go.dev/net#Listen)
    - [CWE-1327: Binding to an Unrestricted IP Address](https://cwe.mitre.org/data/definitions/1327.html)

_New in version 0.8.1_

"""  # noqa: E501
from typing import Optional

from precli.core import utils
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.i18n import _
from precli.rules import Rule


INADDR_ANY = "0.0.0.0"
IN6ADDR_ANY = "[::]"


class NetUnrestrictedBind(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unrestricted_bind",
            description=__doc__,
            cwe_id=1327,
            message=_(
                "Binding to '{0}' exposes the application on all network "
                "interfaces, increasing the risk of unauthorized access."
            ),
        )

    def analyze_call_expression(
        self, context: dict, call: Call
    ) -> Optional[Result]:
        if call.name_qualified not in ("net.Listen",):
            return

        arg = call.get_argument(position=1, name="address")
        # TODO: Go needs to have string argument support
        # if not arg.is_str:
        #    return

        address = arg.value
        if ":" in address:
            address = tuple(address.rsplit(":", 1))
        else:
            address = (address,)

        # In Go, "" instructs to bind to all IPv4 and IPv6 addresses if
        # a dual-stack OS. There is no localhost equivalent.
        if utils.to_str(address[0]) in ("", INADDR_ANY):
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description=_(
                    "Use the localhost address to restrict binding."
                ),
                inserted_content=f'"127.0.0.1:{address[1]}"',
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
                description=_(
                    "Use the localhost address to restrict binding."
                ),
                inserted_content=f'"[::1]:{address[1]}"',
            )
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format("IN6ADDR_ANY ([::])"),
                fixes=fixes,
            )
