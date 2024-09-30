# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `SMTP` without Timeout

The `smtplib.SMTP`, `smtplib.SMTP_SSL`, and `smtplib.LMTP` classes are used
to send emails via the Simple Mail Transfer Protocol (SMTP). These classes
can establish network connections to mail servers and by default do not
specify a timeout for network operations. If a timeout is not specified,
the connection may block indefinitely, leading to potential resource
exhaustion or application hang-ups, particularly in production environments
or network failure scenarios.

This rule enforces that a timeout parameter must be provided when
instantiating `smtplib.SMTP`, `smtplib.SMTP_SSL`, or `smtplib.LMTP` to prevent
the possibility of indefinite blocking.

Failing to specify a timeout in these functions may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="5" title="smtplib_smtp_no_timeout.py"
import smtplib
import ssl


server = smtplib.SMTP("smtp.example.com", 587)
server.starttls(context=ssl.create_default_context())
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/smtplib/examples/smtplib_smtp_no_timeout.py
    ⚠️  Warning on line 10 in tests/unit/rules/python/stdlib/smtplib/examples/smtplib_smtp_no_timeout.py
    PY040: Synchronous Access of Remote Resource without Timeout
    The class 'smtplib.SMTP' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `smtplib.SMTP`,
`smtplib.SMTP_SSL`, or `smtplib.LMTP`. This ensures that if the mail server
is unreachable or unresponsive, the connection attempt will fail after a set
period, preventing indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `smtplib`.


```python linenums="1" hl_lines="5" title="smtplib_smtp_no_timeout.py"
import smtplib
import ssl


server = smtplib.SMTP("smtp.example.com", 587, timeout=10)
server.starttls(context=ssl.create_default_context())
```

# See also

!!! info
    - [smtplib.SMTP — smtplib — SMTP protocol client](https://docs.python.org/3/library/smtplib.html#smtplib.SMTP)
    - [smtplib.SMTP_SSL — smtplib — SMTP protocol client](https://docs.python.org/3/library/smtplib.html#smtplib.SMTP_SSL)
    - [smtplib.LMTP — smtplib — SMTP protocol client](https://docs.python.org/3/library/smtplib.html#smtplib.LMTP)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SmtplibNoTimeout(Rule):
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
            "smtplib.SMTP",
            "smtplib.SMTP_SSL",
            "smtplib.LMTP",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if call.name_qualified == "smtplib.SMTP":
            # SMTP(
            #    host='',
            #    port=0,
            #    local_hostname=None,
            #    timeout=GLOBAL_TIMEOUT,
            #    source_address=None
            # )
            argument = call.get_argument(position=3, name="timeout")
        elif call.name_qualified == "smtplib.SMTP_SSL":
            # SMTP_SSL(
            #    host=''
            #    port=0,
            #    local_hostname=None,
            #    *,
            #    timeout=GLOBAL_TIMEOUT,
            #    source_address=None,
            #    context=None
            # )
            argument = call.get_argument(name="timeout")
        elif call.name_qualified == "smtplib.LMTP":
            # LMTP(
            #    host=''
            #    port=2003,
            #    local_hostname=None,
            #    source_address=None,
            #    timeout=GLOBAL_TIMEOUT
            # )
            argument = call.get_argument(position=4, name="timeout")

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
