# Copyright 2024 Secure Sauce LLC
r"""
# Cleartext Transmission of Sensitive Information in the `nntplib` Module

The Python module `nntplib` provides a number of functions for accessing
NNTP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module nntplib should only in a secure mannner to protect sensitive
data when accessing NNTP servers.

# Example

```python linenums="1" hl_lines="5" title="nntplib_nntp_context_mgr.py"
import nntplib


with nntplib.NNTP("news.gmane.io") as n:
    n.login("user", "password")
    n.group("gmane.comp.python.committers")
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_context_mgr.py
    ⛔️ Error on line 5 in tests/unit/rules/python/stdlib/nntplib/examples/nntplib_nntp_context_mgr.py
    PY012: Cleartext Transmission of Sensitive Information
    The 'nntplib.NNTP.login' function will transmit authentication information such as a user, password  in cleartext.
    ```

# Remediation

If the NNTP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using `NNTP_SSL` class.
Alternatively, the `starttls` function can be used to enter a secure session.

```python linenums="1" hl_lines="4" title="nntplib_nntp_context_mgr.py"
import nntplib


with nntplib.NNTP_SSL('news.gmane.io') as n:
    n.login("user", "password")
    n.group('gmane.comp.python.committers')
```

# See also

!!! info
    - [nntplib — NNTP protocol client](https://docs.python.org/3/library/nntplib.html)
    - [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

_New in version 0.1.9_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class NntpCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            description=__doc__,
            cwe_id=319,
            message="The NNTP protocol can transmit data in cleartext without "
            "encryption.",
            wildcards={
                "nntplib.*": [
                    "NNTP",
                ]
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in ["nntplib.NNTP.login"]:
            return

        symbol = context["symtab"].get(call.var_node.text.decode())
        if "starttls" in [
            x.identifier_node.text.decode() for x in symbol.call_history
        ]:
            return

        init_call = symbol.call_history[0]
        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=init_call.identifier_node),
            description="Use the 'NNTP_SSL' module to secure the "
            "connection.",
            inserted_content="NNTP_SSL",
        )

        return Result(
            rule_id=self.id,
            location=Location(node=call.identifier_node),
            message=f"The '{call.name_qualified}' function will "
            f"transmit authentication information such as a user, "
            "password in cleartext.",
            fixes=fixes,
        )
