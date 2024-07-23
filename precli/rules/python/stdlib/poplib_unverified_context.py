# Copyright 2024 Secure Sauce LLC
r"""
# Improper Certificate Validation Using `poplib`

The Python class `poplib.POP3_SSL` by default creates an SSL context that
does not verify the server's certificate if the context parameter is unset or
has a value of None. This means that an attacker can easily impersonate a
legitimate server and fool your application into connecting to it.

If you use `poplib.POP3_SSL` or `stls` without a context set, you are
opening your application up to a number of security risks, including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

# Example

```python linenums="1" hl_lines="5" title="poplib_pop3_ssl_context_unset.py"
import getpass
import poplib


M = poplib.POP3_SSL("localhost")
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_ssl_context_unset.py
    ⚠️  Warning on line 5 in tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_ssl_context_unset.py
    PY025: Improper Certificate Validation
    The 'poplib.POP3_SSL' function does not properly validate certificates when context is unset or None.
    ```

# Remediation

Set the value of the `context` keyword argument to
`ssl.create_default_context()` to ensure the connection is fully verified.

```python linenums="1" hl_lines="3 8" title="poplib_pop3_ssl_context_unset.py"
import getpass
import poplib
import ssl


M = poplib.POP3_SSL(
    "localhost",
    context=ssl.create_default_context(),
)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
```

# See also

!!! info
    - [poplib.POP3_SSL — POP3 protocol client](https://docs.python.org/3/library/poplib.html#poplib.POP3_SSL)
    - [poplib.POP3.stls — POP3 protocol client](https://docs.python.org/3/library/poplib.html#poplib.POP3.stls)
    - [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#best-defaults)
    - [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


CONTEXT_FIX = "ssl.create_default_context()"


class PoplibUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            description=__doc__,
            cwe_id=295,
            message="The '{0}' function does not properly validate "
            "certificates when context is unset or None.",
            wildcards={
                "poplib.*": [
                    "POP3",
                    "POP3_SSL",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "poplib.POP3_SSL",
            "poplib.POP3.stls",
        ]:
            return

        if call.name_qualified == "poplib.POP3_SSL":
            ssl_context = call.get_argument(name="context")
        else:
            ssl_context = call.get_argument(position=0, name="context")
        if ssl_context.value is not None:
            return

        if ssl_context.node is not None:
            result_node = ssl_context.node
            fix_node = ssl_context.node
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
