# Copyright 2024 Secure Saurce LLC
r"""
# Improper Certificate Validation Using `ftplib`

The Python class `ftplib.FTP_TLS` by default creates an SSL context that does
not verify the server's certificate if the context parameter is unset or has
a value of None. This means that an attacker can easily impersonate a
legitimate server and fool your application into connecting to it.

If you use `ftplib.FTP_TLS` without a context set, you are opening your
application up to a number of security risks, including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

## Example

```python
import ftplib


with ftplib.FTP_TLS("ftp.us.debian.org") as ftp:
    ftp.cwd("debian")
    ftp.retrlines("LIST")
```

## Remediation

Set the value of the `context` keyword argument to
`ssl.create_default_context()` to ensure the connection is fully verified.

```python
import ftplib
import ssl


with ftplib.FTP_TLS(
    "ftp.us.debian.org",
    context=ssl.create_default_context(),
) as ftp:
    ftp.cwd("debian")
    ftp.retrlines("LIST")
```

## See also

- [ftplib — FTP protocol client](https://docs.python.org/3/library/ftplib.html#ftplib.FTP_TLS)
- [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#best-defaults)
- [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


CONTEXT_FIX = "ssl.create_default_context()"


class FtplibUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            description=__doc__,
            cwe_id=295,
            message="The '{0}' function does not properly validate "
            "certificates when context is unset or None.",
            wildcards={
                "ftplib.*": [
                    "FTP_TLS",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in ["ftplib.FTP_TLS"]:
            return

        context_arg = call.get_argument(name="context")
        if context_arg.value is not None:
            return

        if context_arg.node is not None:
            result_node = context_arg.node
            fix_node = context_arg.node
            content = CONTEXT_FIX
        else:
            result_node = call.function_node
            arg_list_node = call.arg_list_node
            fix_node = arg_list_node
            args = [
                child.text.decode() for child in arg_list_node.named_children
            ]
            args.append(f"context={CONTEXT_FIX}")
            content = f"({', '.join(args)})"

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=fix_node),
            description=f"Pass {CONTEXT_FIX} to safely validate certificates.",
            inserted_content=content,
        )
        return Result(
            rule_id=self.id,
            location=Location(node=result_node),
            message=self.message.format(call.name_qualified),
            fixes=fixes,
        )
