# Copyright 2024 Secure Sauce LLC
r"""
# Cleartext Transmission of Sensitive Information in the `ftplib` Module

The Python module `ftplib` provides a number of functions for accessing FTP
servers. However, the module does not provide any security features. This
means that data transmitted over the network, including passwords, is sent
in cleartext. This makes it possible for attackers to intercept and read
this data.

The Python module ftplib should not be used for accessing FTP servers that
contain sensitive data. There are a number of alternatives to ftplib that
provide security features. These alternatives should be used instead of
ftplib for accessing sensitive data.

# Example

```python linenums="1" hl_lines="4 5" title="ftplib_ftp_login.py"
import ftplib


ftp = ftplib.FTP("ftp.us.debian.org")
ftp.login("user", "password")

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/ftplib/examples/ftplib_ftp_login.py
    ⚠️  Warning on line 4 in tests/unit/rules/python/stdlib/ftplib/examples/ftplib_ftp_login.py
    PY003: Cleartext Transmission of Sensitive Information
    The FTP protocol can transmit data in cleartext without encryption.

    ⛔️ Error on line 5 in tests/unit/rules/python/stdlib/ftplib/examples/ftplib_ftp_login.py
    PY003: Cleartext Transmission of Sensitive Information
    The 'ftplib.FTP.login' function will transmit the password argument in cleartext.
    ```

# Remediation

If the FTP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using `FTP_TLS` class. It's also
important to call `prot_p()` to secure the data connection.

```python linenums="1" hl_lines="4 6" title="ftplib_ftp_login.py"
import ftplib


ftp = ftplib.FTP_TLS("ftp.us.debian.org")
ftp.login("user", "password")
ftp.prot_p()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
```

# Alternatives to ftplib

There are a number of alternatives to ftplib that provide security features.
These alternatives include:

 - `Paramiko`: Paramiko is a Python module that provides secure access to
   SSH and SFTP servers. Paramiko uses encryption to protect data
   transmitted over the network.

 - `Twisted`: Twisted is a Python framework that provides a number of
   network protocols, including SSH. Twisted can be used to create secure
   SFTP clients and servers.

## See also

!!! info
    - [ftplib — FTP protocol client](https://docs.python.org/3/library/ftplib.html)
    - [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
    - [Paramiko](https://www.paramiko.org/)
    - [Twisted](https://twisted.org/)

_New in version 0.1.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class FtpCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            description=__doc__,
            cwe_id=319,
            message="The FTP protocol can transmit data in cleartext without "
            "encryption.",
            wildcards={
                "ftplib.*": [
                    "FTP",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified in ["ftplib.FTP"]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.identifier_node),
                description="Use the 'FTP_TLS' module to secure the "
                "connection.",
                inserted_content="FTP_TLS",
            )

            # TODO(ericwb): Default of FTP_TLS context=None creates unsecure
            # _create_unverified_context. Therefore need to suggest
            # create_default_context as part of fix.

            # TODO(ericwb): the fix should also call prot_p() to secure the
            # data connection

            if call.get_argument(position=2, name="passwd").value is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(node=call.function_node),
                    level=Level.ERROR,
                    message=f"The '{call.name_qualified}' module will "
                    f"transmit the password argument in cleartext.",
                    fixes=fixes,
                )
            else:
                return Result(
                    rule_id=self.id,
                    location=Location(node=call.function_node),
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
        if call.name_qualified in ["ftplib.FTP.login"]:
            if call.get_argument(position=1, name="passwd").value is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(node=call.identifier_node),
                    level=Level.ERROR,
                    message=f"The '{call.name_qualified}' function will "
                    f"transmit the password argument in cleartext.",
                )
