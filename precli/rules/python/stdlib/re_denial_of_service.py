# Copyright 2024 Secure Saurce LLC
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

## Examples

```python
import re


pattern = re.compile('(a+)+$')
result = pattern.match('aaaaaaaaaaaaaaaaaaaa!')
```

## Remediation

When using Python's re module to compile or match regular expressions, ensure
that patterns are designed to avoid ambiguous repetition and nested
quantifiers that can cause catastrophic backtracking. Regular expressions
should be reviewed and tested for efficiency and resistance to DoS attacks.

```python
import re


pattern = re.compile('a+$')
result = pattern.match('aaaaaaaaaaaaaaaaaaaa!')
```

## See also

- [re — Regular expression operations](https://docs.python.org/3/library/re.html)
- [Regular expression Denial of Service - ReDoS OWASP Foundation](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
- [CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core import redos
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
            targets=("call"),
            wildcards={},
            config=Config(level=Level.ERROR),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

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
