# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `NNTP` without Timeout

The `nntplib.NNTP` and `nntplib.NNTP_SSL` classes are used to connect to
Network News Transfer Protocol (NNTP) servers for accessing Usenet articles.
These classes establish network connections with NNTP servers, and by
default, they do not enforce a timeout on these connections. Without a
timeout, the application may block indefinitely if the NNTP server is slow
or unresponsive, leading to resource exhaustion, Denial of Service (DoS), or
reduced application responsiveness.

This rule ensures that a timeout parameter is provided when creating
instances of `nntplib.NNTP` or `nntplib.NNTP_SSL` to prevent the risk of
indefinite blocking.

Failing to specify a timeout in these classes may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="5" title="nntplib_nntp_no_timeout.py"
import nntplib
import ssl


nntp = nntplib.NNTP("nntp.example.com")
nntp.starttls(ssl.create_default_context())
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_no_timeout.py
    ⚠️  Warning on line 10 in tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_no_timeout.py
    PY042: Synchronous Access of Remote Resource without Timeout
    The class 'nntplib.NNTP' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `nntplib.NNTP` or
`nntplib.NNTP_SSL`. This ensures that if the mail server is unreachable or
unresponsive, the connection attempt will fail after a set period, preventing
indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `nntplib`.

```python linenums="1" hl_lines="5" title="nntplib_nntp_no_timeout.py"
import nntplib
import ssl


nntp = nntplib.NNTP("nntp.example.com", timeout=5)
nntp.starttls(ssl.create_default_context())
```

# See also

!!! info
    - [nntplib.NNTP — nntplib — IMAP4 protocol client](https://docs.python.org/3/library/nntplib.html#nntplib.NNTP)
    - [nntplib.NNTP_SSL — nntplib — IMAP4 protocol client](https://docs.python.org/3/library/nntplib.html#nntplib.NNTP_SSL)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class NntplibNoTimeout(Rule):
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
            "nntplib.NNTP",
            "nntplib.NNTP_SSL",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if call.name_qualified == "nntplib.NNTP":
            # NNTP(
            #    host,
            #    port=119,
            #    user=None,
            #    password=None,
            #    readermode=None,
            #    usenetrc=False,
            #    timeout=GLOBAL_TIMEOUT
            # )
            argument = call.get_argument(position=6, name="timeout")
        elif call.name_qualified == "nntplib.NNTP_SSL":
            # NNTP_SSL(
            #    host,
            #    port=563,
            #    user=None,
            #    password=None,
            #    ssl_context=None,
            #    readermode=None,
            #    usenetrc=False,
            #    timeout=GLOBAL_TIMEOUT
            # )
            argument = call.get_argument(position=7, name="timeout")

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
