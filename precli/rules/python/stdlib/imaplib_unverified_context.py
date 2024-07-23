# Copyright 2024 Secure Sauce LLC
r"""
# Improper Certificate Validation Using `imaplib`

The Python class `imaplib.IMAP4_SSL` by default creates an SSL context that
does not verify the server's certificate if the context parameter is unset or
has a value of None. This means that an attacker can easily impersonate a
legitimate server and fool your application into connecting to it.

If you use `imaplib.IMAP4_SSL` or `starttls` without a context set, you are
opening your application up to a number of security risks, including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

# Example

```python linenums="1" hl_lines="5" title="imaplib_imap4_ssl_context_unset.py"
import getpass
import imaplib


imap4 = imaplib.IMAP4_SSL("domain.org")
imap4.login(getpass.getuser(), getpass.getpass())
imap4.select()
typ, data = imap4.search(None, "ALL")
for num in data[0].split():
    typ, data = imap4.fetch(num, "(RFC822)")
    print(f"Message {num}\n{data[0][1]}\n")
imap4.close()
imap4.logout()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/imaplib/examples/imaplib_imap4_ssl_context_unset.py
    ⚠️  Warning on line 5 in tests/unit/rules/python/stdlib/imaplib/examples/imaplib_imap4_ssl_context_unset.py
    PY023: Improper Certificate Validation
    The 'imaplib.IMAP4_SSL' function does not properly validate certificates when context is unset or None.
    ```

# Remediation

Set the value of the `ssl_context` keyword argument to
`ssl.create_default_context()` to ensure the connection is fully verified.

```python linenums="1" hl_lines="3 8" title="imaplib_imap4_ssl_context_unset.py"
import getpass
import imaplib
import ssl


imap4 = imaplib.IMAP4_SSL(
    "domain.org",
    ssl_context=ssl.create_default_context(),
)
imap4.login(getpass.getuser(), getpass.getpass())
imap4.select()
typ, data = imap4.search(None, "ALL")
for num in data[0].split():
    typ, data = imap4.fetch(num, "(RFC822)")
    print(f"Message {num}\n{data[0][1]}\n")
imap4.close()
imap4.logout()
```

# See also

!!! info
    - [imaplib.IMAP4_SSL — IMAP4 protocol client](https://docs.python.org/3/library/imaplib.html#imaplib.IMAP4_SSL)
    - [imaplib.IMAP4.starttls — IMAP4 protocol client](https://docs.python.org/3/library/imaplib.html#imaplib.IMAP4.starttls)
    - [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#best-defaults)
    - [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


CONTEXT_FIX = "ssl.create_default_context()"


class ImaplibUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            description=__doc__,
            cwe_id=295,
            message="The '{0}' function does not properly validate "
            "certificates when context is unset or None.",
            wildcards={
                "imaplib.*": [
                    "IMAP4",
                    "IMAP4_SSL",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "imaplib.IMAP4_SSL",
            "imaplib.IMAP4.starttls",
        ]:
            return

        if call.name_qualified == "imaplib.IMAP4_SSL":
            ssl_context = call.get_argument(name="ssl_context")
        else:
            ssl_context = call.get_argument(position=0, name="ssl_context")
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
            args.append(f"ssl_context={CONTEXT_FIX}")
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
