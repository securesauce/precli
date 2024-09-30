# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `Telnet` without Timeout

The `telnetlib.Telnet` class and the `telnetlib.Telnet.open()` method are
used to establish a connection to a remote server using the Telnet protocol.
By default, these operations do not enforce a timeout on the connection,
which can lead to indefinite blocking if the server is unresponsive. This
can result in resource exhaustion, application hanging, or Denial of Service
(DoS) vulnerabilities, especially in networked or production environments.

This rule ensures that a timeout parameter is provided when using
`telnetlib.Telnet` and `telnetlib.Telnet.open()` to prevent the risk of
indefinite blocking during network communications.

Failing to specify a timeout in these classes may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="4" title="telnetlib_telnet_no_timeout.py"
import telnetlib


telnet = telnetlib.Telnet("example.com", 23)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/telnetlib/examples/telnetlib_telnet_no_timeout.py
    ⚠️  Warning on line 9 in tests/unit/rules/python/stdlib/telnetlib/examples/telnetlib_telnet_no_timeout.py
    PY044: Synchronous Access of Remote Resource without Timeout
    The class 'telnetlib.Telnet' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `telnetlib.Telnet` or
`telnetlib.Telnet.open()`. This ensures that if the mail server is unreachable
or unresponsive, the connection attempt will fail after a set period,
preventing indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `telnetlib`.

```python linenums="1" hl_lines="4" title="telnetlib_telnet_no_timeout.py"
import telnetlib


telnet = telnetlib.Telnet("example.com", 23, timeout=5)
```

# See also

!!! info
    - [telnetlib.Telnet — telnetlib — Telnet client](https://docs.python.org/3/library/telnetlib.html#telnetlib.Telnet)
    - [telnetlib.Telnet.open — telnetlib — Telnet client](https://docs.python.org/3/library/telnetlib.html#telnetlib.Telnet.open)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class TelnetlibNoTimeout(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="no_timeout",
            description=__doc__,
            cwe_id=1088,
            message="The class '{0}' is used without a timeout, which may "
            "cause the application to block indefinitely if the remote server "
            "does not respond.",
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in (
            "telnetlib.Telnet",
            "telnetlib.Telnet.open",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if (
            call.name_qualified == "telnetlib.Telnet"
            and call.get_argument(position=0, name="host").node is None
        ):
            return

        # Telnet(host=None, port=0, timeout=GLOBAL_TIMEOUT)
        # Telnet.open(self, host, port=0, timeout=GLOBAL_TIMEOUT)
        argument = call.get_argument(position=2, name="timeout")
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
            # If the timeout parameter is set to be zero, the class will raise
            # a ValueError to prevent the creation of a non-blocking socket. A
            # negative value also raises ValueError. So there is no need to
            # check for these values.
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
