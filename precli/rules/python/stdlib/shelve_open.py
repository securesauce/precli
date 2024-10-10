# Copyright 2024 Secure Sauce LLC
r"""
# Deserialization of Untrusted Data in the `shelve` Module

The Python `shelve` module provides a way to store Python objects in a file.
It is backed by the pickle module, which is a serialization format that can
be used to store arbitrary Python objects.

However, it is important to be aware that the shelve module is not secure
against malicious data. For example, a malicious shelf could be used to
cause the decoder to execute arbitrary code.

# Example

```python linenums="1" hl_lines="4" title="shelve_open_context_mgr.py"
import shelve


with shelve.open("db.dat") as db:
    flag = "key" in db
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/shelve/examples/shelve_open_context_mgr.py
    ⚠️  Warning on line 4 in tests/unit/rules/python/stdlib/shelve/examples/shelve_open_context_mgr.py
    PY015: Deserialization of Untrusted Data
    Potential unsafe usage of 'shelve.open' that can allow instantiation of arbitrary objects.
    ```

# Remediation

To avoid this vulnerability, it is important to only use the shelve module
with data from trusted sources. If you are using the shelve module with
data from an untrusted source, you should first sanitize the data to remove
any potential malicious code.

# See also

!!! info
    - [shelve — Python object persistence](https://docs.python.org/3/library/shelve.html)
    - [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

_New in version 0.1.0_

"""  # noqa: E501
from typing import Optional

from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ShelveOpen(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            description=__doc__,
            cwe_id=502,
            message="Potential unsafe usage of '{0}' that can allow "
            "instantiation of arbitrary objects.",
        )

    def analyze_call(self, context: dict, call: Call) -> Optional[Result]:
        if call.name_qualified in ["shelve.open", "shelve.DbfilenameShelf"]:
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
