# Copyright 2024 Secure Sauce LLC
r"""
# Improper Certificate Validation Using `smtplib`

The Python class `smtplib.SMTP_SSL` by default creates an SSL context that
does not verify the server's certificate if the context parameter is unset or
has a value of None. This means that an attacker can easily impersonate a
legitimate server and fool your application into connecting to it.

If you use `smtplib.SMTP_SSL` or `starttls` without a context set, you are
opening your application up to a number of security risks, including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

# Example

```python linenums="1" hl_lines="25" title="smtplib_smtp_ssl_context_unset.py"
import smtplib


def prompt(prompt):
    return input(prompt).strip()


fromaddr = prompt("From: ")
toaddrs = prompt("To: ").split()
print("Enter message, end with ^D (Unix) or ^Z (Windows):")

# Add the From: and To: headers at the start!
msg = "From: {}\r\nTo: {}\r\n\r\n".format(fromaddr, ", ".join(toaddrs))
while True:
    try:
        line = input()
    except EOFError:
        break
    if not line:
        break
    msg = msg + line

print("Message length is", len(msg))

server = smtplib.SMTP_SSL("localhost")
server.login("user", "password")
server.set_debuglevel(1)
server.sendmail(fromaddr, toaddrs, msg)
server.quit()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/smtplib/examples/smtplib_smtp_ssl_context_unset.py
    ⚠️  Warning on line 25 in tests/unit/rules/python/stdlib/smtplib/examples/smtplib_smtp_ssl_context_unset.py
    PY026: Improper Certificate Validation
    The 'smtplib.SMTP_SSL' function does not properly validate certificates when context is unset or None.
    ```

# Remediation

Set the value of the `context` keyword argument to
`ssl.create_default_context()` to ensure the connection is fully verified.

```python linenums="1" hl_lines="2 28" title="smtplib_smtp_ssl_context_unset.py"
import smtplib
import ssl


def prompt(prompt):
    return input(prompt).strip()


fromaddr = prompt("From: ")
toaddrs = prompt("To: ").split()
print("Enter message, end with ^D (Unix) or ^Z (Windows):")

# Add the From: and To: headers at the start!
msg = "From: {}\r\nTo: {}\r\n\r\n".format(fromaddr, ", ".join(toaddrs))
while True:
    try:
        line = input()
    except EOFError:
        break
    if not line:
        break
    msg = msg + line

print("Message length is", len(msg))

server = smtplib.SMTP_SSL(
    "localhost",
    context=ssl.create_default_context(),
)
server.login("user", "password")
server.set_debuglevel(1)
server.sendmail(fromaddr, toaddrs, msg)
server.quit()
```

# See also

!!! info
    - [smtplib.SMTP_SSL — SMTP protocol client](https://docs.python.org/3/library/smtplib.html#smtplib.SMTP_SSL)
    - [smtplib.SMTP.starttls — SMTP protocol client](https://docs.python.org/3/library/smtplib.html#smtplib.SMTP.starttls)
    - [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#best-defaults)
    - [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


CONTEXT_FIX = "ssl.create_default_context()"


class SmtplibUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            description=__doc__,
            cwe_id=295,
            message="The '{0}' function does not properly validate "
            "certificates when context is unset or None.",
            wildcards={
                "smtplib.*": [
                    "SMTP",
                    "SMTP_SSL",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "smtplib.SMTP_SSL",
            "smtplib.SMTP.starttls",
        ]:
            return

        if call.name_qualified == "smtplib.SMTP_SSL":
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
