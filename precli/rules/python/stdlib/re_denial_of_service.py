# Copyright 2024 Secure Sauce LLC
r"""
# Inefficient Regular Expression Complexity in `re` Module

Patterns in Python's re module that are susceptible to catastrophic
backtracking. Such patterns can lead to performance issues and may cause
a Denial-of-Service (DoS) condition in applications by consuming an
excessive amount of CPU time on certain inputs Vulnerability Explanation

Catastrophic backtracking occurs in regex evaluation when the engine
tries to match complex patterns that contain nested quantifiers or
ambiguous constructs. In certain cases, especially with maliciously
crafted input, this can lead to an exponential number of combinations
being checked, severely impacting application performance and potentially
causing it to hang or crash.

# Examples

```python linenums="1" hl_lines="5" title="re_compile.py"
import re


IPv6address = r"([A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+"
reg = re.compile(IPv6address)
reg.search("http://[:::::::::::::::::::::::::::::::::::::::]/path")
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/re/examples/re_compile.py
    ⛔️ Error on line 5 in tests/unit/rules/python/stdlib/re/examples/re_compile.py
    PY033: Inefficient Regular Expression Complexity
    The call to 're.compile'' with regex pattern 'r"([A-Fa-f0-9:]+:+)+[A-Fa-f0-9]+"'' is susceptible to catastrophic backtracking and may cause performance degradation.
    ```

# Remediation

When using Python's re module to compile or match regular expressions, ensure
that patterns are designed to avoid ambiguous repetition and nested
quantifiers that can cause catastrophic backtracking. Regular expressions
should be reviewed and tested for efficiency and resistance to DoS attacks.

```python linenums="1" hl_lines="4" title="re_compile.py"
import re


IPv6address = r"([A-Fa-f0-9:]+[:$])[A-Fa-f0-9]{1,4}"
reg = re.compile(IPv6address)
reg.search("http://[:::::::::::::::::::::::::::::::::::::::]/path")
```

# See also

!!! info
    - [re — Regular expression operations](https://docs.python.org/3/library/re.html)
    - [Regular expression Denial of Service - ReDoS OWASP Foundation](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
    - [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core import redos
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ReDenialOfService(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="regex_denial_of_service",
            description=__doc__,
            cwe_id=1333,
            message="The call to '{0}'' with regex pattern '{1}'' is "
            "susceptible to catastrophic backtracking and may cause "
            "performance degradation.",
            wildcards={},
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "re.compile",
            "re.search",
            "re.match",
            "re.fullmatch",
            "re.split",
            "re.findall",
            "re.finditer",
            "re.sub",
            "re.subn",
        ]:
            return

        arg = call.get_argument(position=0, name="pattern")
        pattern = arg.value
        if not isinstance(pattern, str):
            return

        if redos.catastrophic(pattern) is True:
            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                message=self.message.format(call.name_qualified, pattern),
            )
