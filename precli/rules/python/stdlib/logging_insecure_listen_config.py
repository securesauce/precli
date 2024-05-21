# Copyright 2024 Secure Sauce LLC
r"""
# Code Injection in Logging Config

The `logging.config.listen()` function allows you to dynamically change the
logging configuration of your application. However, if you set the verify
argument to False, you are opening yourself up to a security vulnerability.
This is because anyone who can connect to the listening socket can send
arbitrary configuration data to your application, which could potentially
allow them to execute arbitrary code.

## Example

```python
import logging.config


thread = logging.config.listen(port=1111, verify=None)
```

## Remediation

The verify argument should be set to a callable function that should verify
whether bytes received on the socket are valid to be processed. One way to
verify the data is to use encryption and/or signing.

```python
import logging.config


def validate(recv: bytes):
    return recv


thread = logging.config.listen(verify=validate)
```

## See also

- [logging.config — Logging configuration](https://docs.python.org/3/library/logging.config.html#module-logging.config)
- [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)

_New in version 0.1.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class InsecureListenConfig(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="code_injection",
            description=__doc__,
            cwe_id=94,
            message="Using '{0}' with unset 'verify' vulnerable to code "
            "injection.",
            wildcards={
                "logging.config.*": [
                    "listen",
                ]
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in ["logging.config.listen"]:
            return

        if call.get_argument(position=1, name="verify").value is None:
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
