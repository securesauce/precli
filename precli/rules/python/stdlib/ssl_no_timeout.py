# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `ssl` without Timeout

The `ssl.get_server_certificate()` function is used to retrieve the
certificate from an SSL-enabled server. By default, this function does not
enforce a timeout on the network connection, which means that an application
could block indefinitely if the server is unresponsive or experiences a
network issue. This can result in resource exhaustion, Denial of Service
(DoS), or unresponsive behavior in the application, especially in production
environments.

This rule ensures that a timeout parameter is provided when calling
`ssl.get_server_certificate()` to prevent the risk of indefinite blocking
during the SSL certificate retrieval process.

If no timeout is specified in `ssl.get_server_certificate()`, the application
may block indefinitely while waiting for a response from the server. This can
lead to resource exhaustion, slow performance, or unresponsive behavior in the
application.

# Example

```python linenums="1" hl_lines="4" title="get_server_certificate_no_timeout.py"
import ssl


cert = ssl.get_server_certificate(("example.com", 443))
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/ssl/examples/get_server_certificate_no_timeout.py
    ⚠️  Warning on line 9 in tests/unit/rules/python/stdlib/ssl/examples/get_server_certificate_no_timeout.py
    PY046: Synchronous Access of Remote Resource without Timeout
    The function 'ssl.get_server_certificate' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

 - Python 3.10 and Later: Always provide a timeout parameter when using
   `ssl.get_server_certificate()`.
 - Python Versions Before 3.10: Use `socket.setdefaulttimeout()` to globally
   enforce a timeout for all socket connections, including those made by
   `ssl.get_server_certificate()`.

```python linenums="1" hl_lines="4" title="get_server_certificate_no_timeout.py"
import ssl


cert = ssl.get_server_certificate(("example.com", 443), timeout=5)
```

# See also

!!! info
    - [ssl.get_server_certificate — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#ssl.get_server_certificate)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SslNoTimeout(Rule):
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
        if call.name_qualified not in ("ssl.get_server_certificate",):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        # get_server_certificate(
        #    addr,
        #    ssl_version=PROTOCOL_TLS_CLIENT,
        #    ca_certs=None,
        #    timeout=GLOBAL_TIMEOUT,
        # )
        argument = call.get_argument(position=3, name="timeout")
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
