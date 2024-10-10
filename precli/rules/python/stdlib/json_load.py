# Copyright 2024 Secure Sauce LLC
r"""
# Deserialization of Untrusted Data in the `json` Module

The Python `json` module provides a way to parse and generate JSON data.
However, it is important to be aware that malicious JSON strings can be used
to attack applications that use the json module. For example, a malicious
JSON string could be used to cause the decoder to consume considerable CPU
and memory resources, which could lead to a denial-of-service attack.

# Example

```python linenums="1" hl_lines="4" title="json_loads.py"
import json


json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]')
```

??? example "Example Output"
    ```
    > precli --enable=all tests/unit/rules/python/stdlib/json/examples/json_loads.py
    ⚠️  Warning on line 4 in tests/unit/rules/python/stdlib/json/examples/json_loads.py
    PY009: Deserialization of Untrusted Data
    Potential unsafe usage of 'json.loads' that can allow instantiation of arbitrary objects.
    ```

# Remediation

To avoid this vulnerability, it is important to only parse JSON data from
trusted sources. If you are parsing JSON data from an untrusted source, you
should first sanitize the data to remove any potential malicious code.

# See also

!!! info
    - [json — JSON encoder and decoder](https://docs.python.org/3/library/json.html)
    - [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)

_New in version 0.1.0_

"""  # noqa: E501
from typing import Optional

from precli.core.call import Call
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class JsonLoad(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            description=__doc__,
            cwe_id=502,
            message="Potential unsafe usage of '{0}' that can allow "
            "instantiation of arbitrary objects.",
            config=Config(enabled=False),
        )

    def analyze_call(self, context: dict, call: Call) -> Optional[Result]:
        if call.name_qualified in [
            "json.load",
            "json.loads",
            "json.JSONDecoder.decode",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
