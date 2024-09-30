# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `IMAP4` without Timeout

The `imaplib.IMAP4` and `imaplib.IMAP4_SSL` classes are used to connect to
IMAP servers for retrieving emails over the Internet Message Access Protocol
(IMAP). By default, these classes do not specify a timeout, which can result
in the application blocking indefinitely while trying to communicate with an
unresponsive server. This can lead to resource exhaustion, Denial of Service
(DoS), or system instability, particularly in production environments where
resilience is critical.

This rule enforces the use of a timeout parameter when creating instances
of `imaplib.IMAP4` and `imaplib.IMAP4_SSL` to avoid the risk of indefinite
blocking and ensure graceful handling of network delays or failures.

Failing to specify a timeout in these classes may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="5" title="imaplib_imap_no_timeout.py"
import imaplib
import ssl


imap = imaplib.IMAP4("imap.example.com")
imap.starttls(ssl.create_default_context())
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/imaplib/examples/imaplib_imap_no_timeout.py
    ⚠️  Warning on line 10 in tests/unit/rules/python/stdlib/imaplib/examples/imaplib_imap_no_timeout.py
    PY041: Synchronous Access of Remote Resource without Timeout
    The class 'imaplib.IMAP4' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `imaplib.IMAP4` or
`imaplib.IMAP4_SSL`. This ensures that if the mail server is unreachable or
unresponsive, the connection attempt will fail after a set period, preventing
indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `imaplib`.

```python linenums="1" hl_lines="5" title="imaplib_imap_no_timeout.py"
import imaplib
import ssl


imap = imaplib.IMAP4("imap.example.com", timeout=5)
imap.starttls(ssl.create_default_context())
```

# See also

!!! info
    - [imaplib.IMAP4 — imaplib — IMAP4 protocol client](https://docs.python.org/3/library/imaplib.html#imaplib.IMAP4)
    - [imaplib.IMAP4_SSL — imaplib — IMAP4 protocol client](https://docs.python.org/3/library/imaplib.html#imaplib.IMAP4_SSL)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ImaplibNoTimeout(Rule):
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
            "imaplib.IMAP4",
            "imaplib.IMAP4_SSL",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if call.name_qualified == "imaplib.IMAP4":
            # IMAP4(host='', port=143, timeout=None)
            argument = call.get_argument(position=2, name="timeout")
        elif call.name_qualified == "imaplib.IMAP4_SSL":
            # IMAP4_SSL(host='', port=993, *, ssl_context=None, timeout=None)
            argument = call.get_argument(name="timeout")

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
