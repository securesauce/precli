# Copyright 2024 Secure Sauce LLC
r"""
# Synchronous Access of `FTP` without Timeout

The `ftplib.FTP` and `ftplib.FTP_TLS` classes are used to establish FTP
connections for transferring files over the network. These classes, along
with the `ftplib.FTP.connect` method, do not enforce a timeout by default, which
can lead to indefinite blocking if the FTP server becomes unresponsive or
experiences a network issue. This can cause resource exhaustion, Denial of
Service (DoS), or reduced application responsiveness, especially in production
environments.

This rule ensures that a timeout parameter is provided when creating
instances of `ftplib.FTP`, `ftplib.FTP_TLS`, and when calling
`ftplib.FTP.connect` to prevent the risk of indefinite blocking during FTP
operations.

Failing to specify a timeout in these classes may cause the application to
block indefinitely while waiting for a response from the mail server. This can
lead to Denial of Service (DoS) vulnerabilities or cause the application to
become unresponsive.

# Example

```python linenums="1" hl_lines="4" title="ftplib_ftp_no_timeout.py"
import ftplib


ftp_server = ftplib.FTP("ftp.example.com")
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/ftplib/examples/ftplib_ftp_no_timeout.py
    ⚠️  Warning on line 9 in tests/unit/rules/python/stdlib/ftplib/examples/ftplib_ftp_no_timeout.py
    PY045: Synchronous Access of Remote Resource without Timeout
    The class 'ftplib.FTP' is used without a timeout, which may cause the application to block indefinitely if the remote server does not respond.
    ```

# Remediation

Always provide a timeout parameter when using `ftplib.FTP`, `ftplib.FTP_TLS`,
or `ftplib.FTP.connect`. This ensures that if the mail server is unreachable
or unresponsive, the connection attempt will fail after a set period,
preventing indefinite blocking and resource exhaustion.

Alternatively, the global default timeout can be set via
`socket.setdefaulttimeout()`. This is a good option to enforce a consistent
timeout for any network library that uses sockets, including `ftplib`.

```python linenums="1" hl_lines="4" title="ftplib_ftp_no_timeout.py"
import ftplib


ftp_server = ftplib.FTP("ftp.example.com", timeout=5)
```

# See also

!!! info
    - [ftplib.FTP — ftplib — FTP protocol client](https://docs.python.org/3/library/ftplib.html#ftplib.FTP)
    - [ftplib.FTP.connect — ftplib — FTP protocol client](https://docs.python.org/3/library/ftplib.html#ftplib.FTP.connect)
    - [ftplib.FTP_TLS — ftplib — FTP protocol client](https://docs.python.org/3/library/ftplib.html#ftplib.FTP_TLS)
    - [socket.setdefaulttimeout — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout)
    - [CWE-1088: Synchronous Access of Remote Resource without Timeout](https://cwe.mitre.org/data/definitions/1088.html)

_New in version 0.6.7_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class FtplibNoTimeout(Rule):
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
            "ftplib.FTP",
            "ftplib.FTP.connect",
            "ftplib.FTP_TLS",
        ):
            return

        symbol = context["global_symtab"].get("GLOBAL_DEFAULT_TIMEOUT")
        if symbol is not None and symbol.value > 0:
            return

        if (
            call.name_qualified in ("ftplib.FTP", "ftplib.FTP_TLS")
            and call.get_argument(position=0, name="host").node is None
        ):
            return

        if call.name_qualified == "ftplib.FTP":
            # FTP(
            #    host='',
            #    user='',
            #    passwd='',
            #    acct='',
            #    timeout=GLOBAL_TIMEOUT,
            #    source_address=None,
            #    *,
            #    encoding='utf-8'
            # )
            argument = call.get_argument(position=4, name="timeout")
        elif call.name_qualified in (
            "ftplib.FTP.connect",
            "ftplib.FTP_TLS.connect",
        ):
            # FTP.connect(
            #    self,
            #    host='',
            #    port=0,
            #    timeout=-999,
            #    source_address=None
            # )
            argument = call.get_argument(position=2, name="timeout")
        elif call.name_qualified == "ftplib.FTP_TLS":
            # FTP_TLS(
            #    host='',
            #    user='',
            #    passwd='',
            #    acct='',
            #    *,
            #    context=None,
            #    timeout=GLOBAL_TIMEOUT,
            #    source_address=None,
            #    encoding='utf-8'
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
