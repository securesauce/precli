# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `POP3` without Timeout

The `poplib.POP3` and `poplib.POP3_SSL` classes are used to connect to mail
servers using the Post Office Protocol version 3 (POP3) for retrieving emails.
By default, these classes do not enforce a timeout on the network connection,
which means that an application could block indefinitely if the mail server
becomes unresponsive or there is a network failure. This can result in resource
exhaustion, Denial of Service (DoS), or unresponsive behavior in the
application.

This rule ensures that a timeout parameter is provided when creating instances
of `poplib.POP3` or `poplib.POP3_SSL` to prevent the risk of indefinite
blocking during network communication.

Failing to specify a timeout in these classes may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="5" title="poplib_pop3_no_timeout.py"
import poplib
import ssl


pop = poplib.POP3("mail.my-mail-server.com")
pop.stls(ssl.create_default_context())
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_no_timeout.py
    ⚠️  Warning on line 10 in tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_no_timeout.py
    PY043: Synchronous Access of Remote Resource without Timeout
    The class 'poplib.POP3' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `poplib.POP3` or
`poplib.POP3_SSL`. This ensures that if the mail server is unreachable or
unresponsive, the connection attempt will fail after a set period, preventing
indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `poplib`.

```python linenums="1" hl_lines="5" title="poplib_pop3_no_timeout.py"
import poplib
import ssl


pop = poplib.POP3("mail.my-mail-server.com", timeout=5)
pop.stls(ssl.create_default_context())
```

# See also

!!! info
    - [poplib.POP3 — poplib — POP3 protocol client](https://docs.python.org/3/library/poplib.html#poplib.POP3)
    - [poplib.POP3_SSL — poplib — POP3 protocol client](https://docs.python.org/3/library/poplib.html#poplib.POP3_SSL)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PoplibNoTimeout(Rule):
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
            "poplib.POP3",
            "poplib.POP3_SSL",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if call.name_qualified == "poplib.POP3":
            # POP3(host, port=110, timeout=GLOBAL_TIMEOUT)
            argument = call.get_argument(position=2, name="timeout")
        elif call.name_qualified == "poplib.POP3_SSL":
            # POP3_SSL(
            #    host,
            #    port=995,
            #    *,
            #    timeout=GLOBAL_TIMEOUT,
            #    context=None,
            # )
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
