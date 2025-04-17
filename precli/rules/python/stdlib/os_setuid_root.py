# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
r"""
# Execution with Unnecessary Privileges using `os` Module

The Python function os.setuid() is used to set the user ID of the current
process. Passing a user ID of 0 to setuid() changes the process’s user to the
root user (superuser). This can lead to privilege escalation, allowing the
current process to execute with root-level permissions, which could be
exploited by malicious actors to gain control over the system.

Processes running with elevated privileges (such as root) can pose significant
security risks if misused. For instance, a vulnerability in such a process
could be leveraged by attackers to compromise the entire system. Therefore,
it is essential to avoid changing the process’s user ID to 0 unless absolutely
necessary and to ensure such usage is thoroughly reviewed and justified.

## Examples

```python linenums="1" hl_lines="4" title="os_setuid_0.py"
import os


os.setuid(0)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/os/examples/os_setuid_0.py
    ⛔️ Error on line 9 in tests/unit/rules/python/stdlib/os/examples/os_setuid_0.py
    PY038: Execution with Unnecessary Privileges
    The function 'os.setuid(0)' escalates the process to run with root (superuser) privileges.
    ```

## Remediation

 - Avoid using setuid(0) unless absolutely necessary: Review whether running
   as the root user is required for the task at hand. It is safer to operate
   with the least privileges necessary.
 - Drop privileges as soon as possible: If elevated privileges are required
   temporarily, ensure that the process drops those privileges immediately
   after performing the necessary tasks.
 - Validate input to avoid malicious manipulation: If input parameters control
   the user ID passed to setuid(), ensure they are securely validated and not
   influenced by untrusted sources.
 - Use alternatives to running as root: If feasible, design your application
   to avoid needing root privileges entirely. Consider utilizing a dedicated
   service or capability that performs the task in a secure, controlled manner.

```python linenums="1" hl_lines="4" title="os_setuid_0.py"
import os


os.setuid(1000)
```

# Default Configuration

```toml
enabled = true
level = "error"
```

## See also

!!! info
    - [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html#os.setuid)
    - [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)
    - [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

_New in version 0.6.6_

"""  # noqa: E501
from typing import Optional

from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.i18n import _
from precli.rules import Rule


class OsSetuidRoot(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unnecessary_privileges",
            description=__doc__,
            cwe_id=250,
            message=_(
                "The function '{0}(0)' escalates the process to run with "
                "root (superuser) privileges."
            ),
        )

    def analyze_call(self, context: dict, call: Call) -> Optional[Result]:
        if call.name_qualified != "os.setuid":
            return

        argument = call.get_argument(position=0, name="uid")
        uid = argument.value

        if isinstance(uid, int) and uid == 0:
            return Result(
                rule_id=self.id,
                location=Location(node=argument.node),
                message=self.message.format(call.name_qualified),
            )
