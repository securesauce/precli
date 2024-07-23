# Copyright 2024 Secure Sauce LLC
r"""
# Cleartext Transmission of Sensitive Information in the `poplib` Module

The Python module `poplib` provides a number of functions for accessing
POP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module poplib should only in a secure mannner to protect sensitive
data when accessing POP servers.

# Example

```python linenums="1" hl_lines="5 6" title="poplib_pop3_pass_.py"
import getpass
import poplib


M = poplib.POP3('localhost')
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i+1)[1]:
        print(j)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_pass_.py
    ⛔️ Error on line 6 in tests/unit/rules/python/stdlib/poplib/examples/poplib_pop3_pass_.py
    PY014: Cleartext Transmission of Sensitive Information
    The 'poplib.POP3.pass_' function will transmit authentication information such as a user, password in cleartext.
    ```

# Remediation

If the POP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using `POP3_SSL` class.
Alternatively, the `stls` function can be used to enter a secure session.

```python linenums="1" hl_lines="5" title="poplib_pop3_pass_.py"
import getpass
import poplib


M = poplib.POP3_SSL('localhost')
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i+1)[1]:
        print(j)
```

# See also

!!! info
    - [poplib — POP3 protocol client](https://docs.python.org/3/library/poplib.html)
    - [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

_New in version 0.1.9_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PopCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            description=__doc__,
            cwe_id=319,
            message="The POP protocol can transmit data in cleartext without "
            "encryption.",
            wildcards={
                "poplib.*": [
                    "POP3",
                ]
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "poplib.POP3.user",
            "poplib.POP3.pass_",
            "poplib.POP3.apop",
            "poplib.POP3.rpop",
        ]:
            return

        symbol = context["symtab"].get(call.var_node.text.decode())
        if "stls" in [
            x.identifier_node.text.decode() for x in symbol.call_history
        ]:
            return

        init_call = symbol.call_history[0]
        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=init_call.identifier_node),
            description="Use the 'POP3_SSL' module to secure the "
            "connection.",
            inserted_content="POP3_SSL",
        )

        return Result(
            rule_id=self.id,
            location=Location(node=call.identifier_node),
            message=f"The '{call.name_qualified}' function will "
            f"transmit authentication information such as a user, "
            "password in cleartext.",
            fixes=fixes,
        )
