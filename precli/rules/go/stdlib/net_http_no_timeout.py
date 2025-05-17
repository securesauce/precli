# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
r"""
# Resource Allocation Without Limits in `net/http` Package

The Go standard library provides convenient functions such as
`net/http.ListenAndServe`, `net/http.ListenAndServeTLS`, `net/http.Serve`, and
`net/http.ServeTLS` to quickly start HTTP and HTTPS servers. However, a
significant security issue with these functions is that they do not allow
developers to specify critical timeout values—such as ReadTimeout,
WriteTimeout, or IdleTimeout—on the server. By default, these timeouts are
unset (zero), meaning the server will wait indefinitely for clients to
send or receive data. This behavior can be exploited by malicious actors
using techniques like Slowloris attacks, where an attacker intentionally
opens many connections and sends data very slowly to exhaust server
resources. Without timeouts, each connection can tie up a goroutine and
file descriptor, leading to resource exhaustion and making the server
susceptible to denial-of-service (DoS) attacks.

Beyond malicious intent, the absence of timeouts also increases the risk
from buggy or misbehaving clients that inadvertently leave connections open,
potentially causing the same resource exhaustion problem. In production
environments, it is critical to protect against both unintentional and
intentional abuse by configuring sensible timeouts on all HTTP servers.
Since the shortcut functions (`ListenAndServe`, etc.) do not provide any
parameters for timeout configuration, developers must instead use an
http.Server struct and explicitly set the timeout fields. Failing to do so
can compromise both the availability and stability of the server, making
this an important security and operational concern.

# Example

```go linenums="1" hl_lines="15" title="net_http_listenandserve.go"
package main

import (
    "io"
    "log"
    "net/http"
)

func main() {
    helloHandler := func(w http.ResponseWriter, req *http.Request) {
        io.WriteString(w, "Hello, world!\n")
    }

    http.HandleFunc("/hello", helloHandler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/go/stdlib/net/examples/net_http_listenandserve.go
    ⚠️  Error on line 15 in tests/unit/rules/go/stdlib/net/examples/net_http_listenandserve.go
    GO007: Allocation of Resources Without Limits or Throttling
    The function 'net/http.ListenAndServe' does not allow timeout values to be set, which may leave the server vulnerable to resource exhaustion or denial-of-service attacks.
    ```

# Remediation

To mitigate resource exhaustion risks, replace with http.Server or similar
with proper timeout values.

```go linenums="1" hl_lines="18-24 26" title="net_http_listenandserve.go"
package main

import (
    "io"
    "log"
    "net/http"
    "time"
)

func main() {
    helloHandler := func(w http.ResponseWriter, req *http.Request) {
        io.WriteString(w, "Hello, world!\n")
    }

    mux := http.NewServeMux()
    mux.HandleFunc("/hello", helloHandler)

    server := &http.Server{
        Addr:         ":8080",
        Handler:      mux,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    log.Fatal(server.ListenAndServe())
}
```

# Default Configuration

```toml
enabled = true
level = "warning"
```

# See also

!!! info
    - [http package - net_http_ListenAndServe - Go Packages](https://pkg.go.dev/net/http#ListenAndServe)
    - [http package - net_http_ListenAndServeTLS - Go Packages](https://pkg.go.dev/net/http#ListenAndServeTLS)
    - [http package - net_http_Serve - Go Packages](https://pkg.go.dev/net/http#Serve)
    - [http package - net_http_ServeTLS - Go Packages](https://pkg.go.dev/net/http#ServeTLS)
    - [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)

_New in version 0.8.1_

"""  # noqa: E501
from typing import Optional

from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.i18n import _
from precli.rules import Rule


class NetHttpNoTimeout(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="resource_allocation_without_limits",
            description=__doc__,
            cwe_id=770,
            message=_(
                "The function '{0}' does not allow timeout values to be set, "
                "which may leave the server vulnerable to resource exhaustion "
                "or denial-of-service attacks."
            ),
        )

    def analyze_call_expression(
        self, context: dict, call: Call
    ) -> Optional[Result]:
        if call.name_qualified not in (
            "net/http.ListenAndServe",
            "net/http.ListenAndServeTLS",
            "net/http.Serve",
            "net/http.ServeTLS",
        ):
            return

        """
        TODO: Fix should be:
        server := &http.Server{
            Addr: ":8080",
            Handler: handler,
            ReadTimeout: 10 * time.Second,
            WriteTimeout: 10 * time.Second,
            IdleTimeout: 60 * time.Second,
        }
        server.ListenAndServe()
        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=call.function_node),
            description=_(
                "To mitigate resource exhaustion risks, replace with "
                "http.Server or similar with proper timeout values."
            ),
            inserted_content="aes.NewCipher",
        )
        """
        return Result(
            rule_id=self.id,
            location=Location(node=call.function_node),
            message=self.message.format(call.name),
            # fixes=fixes,
        )
