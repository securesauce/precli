# Copyright 2024 Secure Sauce LLC
r"""
# Deserialization of Untrusted Data in `pickle` Module

The Python `pickle` module is a serialization module that can be used to
serialize and deserialize Python objects. However, pickle is not a secure
serialization format and should not be used to serialize sensitive data.

Pickle is not secure because it can be used to deserialize malicious code. For
example, an attacker could create a pickle file that contains malicious code
and then trick a user into opening the file. When the user opens the file,
the malicious code would be executed.

# Example

```python linenums="1" hl_lines="9" title="pickle_loads.py"
import pickle


def load_pickle_file(file_path):
    with open(file_path, 'rb') as file:
        data = file.read()

    # WARNING: Unpickle data without proper validation
    obj = pickle.loads(data)
    return obj

# Example usage (assuming 'malicious.pickle' contains malicious code)
pickle_file = 'malicious.pickle'
loaded_object = load_pickle_file(pickle_file)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/pickle/examples/pickle_loads.py
    ⚠️  Warning on line 9 in tests/unit/rules/python/stdlib/pickle/examples/pickle_loads.py
    PY013: Deserialization of Untrusted Data
    Potential unsafe usage of 'pickle.loads' that can allow instantiation of arbitrary objects.
    ```

# Remediation

Consider signing data with hmac if you need to ensure that pickle data has
not been tampered with.

Alternatively if you need to serialize sensitive data, you could use a
secure serialization format, such as JSON or XML. These formats are designed
to be secure and cannot be used to execute malicious code.

# See also

!!! info
    - [pickle — Python object serialization](https://docs.python.org/3/library/pickle.html)
    - [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
    - [json — JSON encoder and decoder](https://docs.python.org/3/library/json.html)

_New in version 0.1.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PickleLoad(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            description=__doc__,
            cwe_id=502,
            message="Potential unsafe usage of '{0}' that can allow "
            "instantiation of arbitrary objects.",
            wildcards={
                "pickle.*": [
                    "load",
                    "loads",
                    "Unpickler",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified in [
            "pickle.load",
            "pickle.loads",
            "pickle.Unpickler",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
