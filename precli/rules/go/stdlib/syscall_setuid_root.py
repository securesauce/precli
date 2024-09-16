# Copyright 2024 Secure Sauce LLC
r"""
# Execution with Unnecessary Privileges using `syscall` Package

The Golang function Setuid() is used to set the user ID of the current
process. Passing a user ID of 0 to Setuid() changes the process’s user to the
root user (superuser). This can lead to privilege escalation, allowing the
current process to execute with root-level permissions, which could be
exploited by malicious actors to gain control over the system.

Processes running with elevated privileges (such as root) can pose significant
security risks if misused. For instance, a vulnerability in such a process
could be leveraged by attackers to compromise the entire system. Therefore,
it is essential to avoid changing the process’s user ID to 0 unless absolutely
necessary and to ensure such usage is thoroughly reviewed and justified.

## Examples

```go linenums="1" hl_lines="11" title="syscall_setuid_0.go"
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setuid(0); err != nil {
        log.Fatalf("Failed to set UID: %v", err)
    }

    fmt.Printf("Running as UID: %d\n", os.Getuid())
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/go/stdlib/syscall/examples/syscall_setuid_0.go
    ⛔️ Error on line 16 in tests/unit/rules/go/stdlib/syscall/examples/syscall_setuid_0.go
    GO004: Execution with Unnecessary Privileges
    The function 'syscall.Setuid(0)' escalates the process to run with root (superuser) privileges.
    ```

## Remediation

 - Avoid using Setuid(0) unless absolutely necessary: Review whether running
   as the root user is required for the task at hand. It is safer to operate
   with the least privileges necessary.
 - Drop privileges as soon as possible: If elevated privileges are required
   temporarily, ensure that the process drops those privileges immediately
   after performing the necessary tasks.
 - Validate input to avoid malicious manipulation: If input parameters control
   the user ID passed to Setuid(), ensure they are securely validated and not
   influenced by untrusted sources.
 - Use alternatives to running as root: If feasible, design your application
   to avoid needing root privileges entirely. Consider utilizing a dedicated
   service or capability that performs the task in a secure, controlled manner.

```go linenums="1" hl_lines="11" title="syscall_setuid_0.go"
package main

import (
    "fmt"
    "log"
    "os"
    "syscall"
)

func main() {
    if err := syscall.Setuid(500); err != nil {
        log.Fatalf("Failed to set UID: %v", err)
    }

    fmt.Printf("Running as UID: %d\n", os.Getuid())
}
```

## See also

!!! info
    - [syscall package - syscall - Go Packages](https://pkg.go.dev/syscall#Setuid)
    - [Principle of Least Privilege](https://en.wikipedia.org/wiki/Principle_of_least_privilege)
    - [CWE-250: Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html)

_New in version 0.6.6_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SyscallSetuidRoot(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="unnecessary_privileges",
            description=__doc__,
            cwe_id=250,
            message="The function '{0}(0)' escalates the process to run with "
            "root (superuser) privileges.",
            config=Config(level=Level.ERROR),
        )

    def analyze_call_expression(
        self, context: dict, call: Call
    ) -> Result | None:
        if call.name_qualified != "syscall.Setuid":
            return

        argument = call.get_argument(position=0, name="uid")
        uid = argument.value

        if isinstance(uid, int) and uid == 0:
            return Result(
                rule_id=self.id,
                location=Location(node=argument.node),
                message=self.message.format(call.name_qualified),
            )
