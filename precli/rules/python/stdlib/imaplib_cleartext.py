# Copyright 2024 Secure Sauce LLC
r"""
# Cleartext Transmission of Sensitive Information in the `imaplib` Module

The Python module `imaplib` provides a number of functions for accessing
IMAP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module imaplib should only in a secure mannner to protect sensitive
data when accessing IMAP servers.

## Example

```python
import getpass
import imaplib


M = imaplib.IMAP4()
M.login(getpass.getuser(), getpass.getpass())
M.select()
typ, data = M.search(None, 'ALL')
for num in data[0].split():
    typ, data = M.fetch(num, '(RFC822)')
    print('Message %s\n%s\n' % (num, data[0][1]))
M.close()
M.logout()
```

## Remediation

If the IMAP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using `IMAP4_SSL` class.
Alternatively, the `starttls` function can be used to enter a secure session.

```python
import getpass
import imaplib


M = imaplib.IMAP4_SSL()
M.login(getpass.getuser(), getpass.getpass())
M.select()
typ, data = M.search(None, 'ALL')
for num in data[0].split():
    typ, data = M.fetch(num, '(RFC822)')
    print('Message %s\n%s\n' % (num, data[0][1]))
M.close()
M.logout()
```

## See also

- [imaplib — IMAP4 protocol client](https://docs.python.org/3/library/imaplib.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)

_New in version 0.1.9_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ImapCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            description=__doc__,
            cwe_id=319,
            message="The IMAP protocol can transmit data in cleartext without "
            "encryption.",
            wildcards={
                "imaplib.*": [
                    "IMAP4",
                ]
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in [
            "imaplib.IMAP4.authenticate",
            "imaplib.IMAP4.login",
            "imaplib.IMAP4.login_cram_md5",
        ]:
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
            description="Use the 'IMAP4_SSL' module to secure the "
            "connection.",
            inserted_content="IMAP4_SSL",
        )

        return Result(
            rule_id=self.id,
            location=Location(node=call.identifier_node),
            message=f"The '{call.name_qualified}' function will "
            f"transmit authentication information such as a user, "
            "password in cleartext.",
            fixes=fixes,
        )
