# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
r"""
# Improper Certificate Validation Using `nntplib`

The Python class `nntplib.NNTP_SSL` by default creates an SSL context that
does not verify the server's certificate if the context parameter is unset or
has a value of None. This means that an attacker can easily impersonate a
legitimate server and fool your application into connecting to it.

If you use `nntplib.NNTP_SSL` or `starttls` without a context set, you are
opening your application up to a number of security risks, including:

- Machine-in-the-middle attacks
- Session hijacking
- Data theft

# Example

```python linenums="1" hl_lines="4" title="nntplib_nntp_ssl_context_unset.py"
import nntplib


s = nntplib.NNTP_SSL("news.gmane.io")
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_ssl_context_unset.py
    ⚠️  Warning on line 4 in tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_ssl_context_unset.py
    PY024: Improper Certificate Validation
    The 'nntplib.NNTP_SSL' function does not properly validate certificates when context is unset or None.
    ```

# Remediation

Set the value of the `context` keyword argument to
`ssl.create_default_context()` to ensure the connection is fully verified.

```python linenums="1" hl_lines="2 7" title="nntplib_nntp_ssl_context_unset.py"
import nntplib
import ssl


s = nntplib.NNTP_SSL(
    "news.gmane.io",
    context=ssl.create_default_context(),
)
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
```

# Default Configuration

```toml
enabled = true
level = "warning"
```

# See also

!!! info
    - [nntplib.NNTP_SSL — NNTP protocol client](https://docs.python.org/3/library/nntplib.html#nntplib.NNTP_SSL)
    - [nntplib.NNTP.starttls — NNTP protocol client](https://docs.python.org/3/library/nntplib.html#nntplib.NNTP.starttls)
    - [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#best-defaults)
    - [CWE-295: Improper Certificate Validation](https://cwe.mitre.org/data/definitions/295.html)

_New in version 0.3.14_

"""  # noqa: E501
from typing import Optional

from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.i18n import _
from precli.rules import Rule


CONTEXT_FIX = "ssl.create_default_context()"


class NntplibUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            description=__doc__,
            cwe_id=295,
            message=_(
                "The '{0}' function does not properly validate certificates "
                "when context is unset or None."
            ),
        )

    def analyze_call(self, context: dict, call: Call) -> Optional[Result]:
        if call.name_qualified not in [
            "nntplib.NNTP_SSL",
            "nntplib.NNTP.starttls",
        ]:
            return

        if call.name_qualified == "nntplib.NNTP_SSL":
            ssl_context = call.get_argument(name="ssl_context")
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
            description=_(
                f"Pass {CONTEXT_FIX} to safely validate certificates."
            ),
            inserted_content=content,
        )
        return Result(
            rule_id=self.id,
            location=Location(node=result_node),
            message=self.message.format(call.name_qualified),
            fixes=fixes,
        )
