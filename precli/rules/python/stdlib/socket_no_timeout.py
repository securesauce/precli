# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `socket` without Timeout

The function `socket.create_connection()` in Python establishes a TCP
connection to a remote host. By default, this function operates synchronously,
meaning it will block indefinitely if no timeout is specified. This behavior
can lead to resource exhaustion or unresponsive applications if the remote
host is slow or unresponsive, creating the risk of a Denial of Service (DoS).

This rule ensures that a timeout is always specified when using
`socket.create_connection()` to prevent indefinite blocking and resource
exhaustion.

Failing to specify a timeout in `socket.create_connection()` may cause the
system or application to block indefinitely while waiting for a connection,
consuming resources unnecessarily and potentially leading to system hangs or
Denial of Service (DoS) vulnerabilities.

# Example

```python linenums="1" hl_lines="4" title="socket_create_connection.py"
import socket


s = socket.create_connection(("127.0.0.1", 80))
s.recv(1024)
s.close()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/socket/examples/socket_create_connection.py
    ⚠️  Warning on line 9 in tests/unit/rules/python/stdlib/socket/examples/socket_create_connection.py
    PY039: Synchronous Access of Remote Resource without Timeout
    The function 'socket.create_connection' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when calling `socket.create_connection()`.
This ensures that if the remote host is unreachable or unresponsive, the
connection attempt will fail after a certain period, releasing resources
and preventing indefinite blocking.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets.

```python linenums="1" hl_lines="4" title="socket_create_connection.py"
import socket


s = socket.create_connection(("127.0.0.1", 80), timeout=5)
s.recv(1024)
s.close()
```

# See also

!!! info
    - [socket.create_connection — Low-level networking interface](https://docs.python.org/3/library/socket.html#socket.create_connection)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SocketNoTimeout(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="no_timeout",
            description=__doc__,
            cwe_id=1088,
            message="The function '{0}' is used without a timeout, which may "
            "cause the application to block indefinitely if the remote server "
            "does not respond.",
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in ("socket.create_connection",):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        # create_connection(
        #    address,
        #    timeout=GLOBAL_TIMEOUT,
        #    source_address=None,
        #    *,
        #    all_errors=False
        # )

        argument = call.get_argument(position=1, name="timeout")
        timeout = argument.value

        if argument.node is None:
            arg_list_node = call.arg_list_node
            fix_node = arg_list_node
            args = [child.string for child in arg_list_node.named_children]
            args.append("timeout=5")
            content = f"({', '.join(args)})"
            result_node = call.arg_list_node
        elif timeout is None:
            fix_node = argument.node
            result_node = argument.node
            content = "5"
        else:
            # A value of zero sets the socket to non-blocking mode. Negative
            # values will raise a ValueError.
            return

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(fix_node),
            description="Set timeout parameter to a small number of seconds.",
            inserted_content=content,
        )
        return Result(
            rule_id=self.id,
            location=Location(node=result_node),
            message=self.message.format(call.name_qualified),
            fixes=fixes,
        )
