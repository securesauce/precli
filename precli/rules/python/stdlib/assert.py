# Copyright 2024 Secure Sauce LLC
r"""
# Improper Check Using `assert` Function

Assertions are typically used during the development phase to catch logic
errors and conditions that should never occur. However, relying on assertions
for security checks or other critical runtime validations is not recommended
because:

- Assertions can be disabled in Python with the -O (optimize) and -OO flags,
  which remove assert statements and sometimes docstrings. If critical checks
  are implemented using assertions, this could lead to security vulnerabilities
  being exposed in production environments where optimizations are enabled.

- Assertions throw exceptions if the condition fails, which, if not properly
  handled, can lead to crashes or other unintended behavior in the application.

Using assertions for non-critical checks during development is common, but for
production code, especially for input validation, error handling, or other
security-sensitive operations, it's important to use proper error handling
mechanisms and validations that do not get removed during optimization.

# Examples

```python linenums="1" hl_lines="2" title="assert.py"
def foobar(a: str = None):
    assert a is not None
    return f"Hello {a}"

foobar("World")
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/assert/examples/assert.py
    ⚠️  Warning on line 2 in tests/unit/rules/python/stdlib/assert/examples/assert.py
    PY001: Improper Check or Handling of Exceptional Conditions
    Assert statements are disabled when optimizations are enabled.
    ```

# Remediation

Use proper error handling mechanism appropriate for production code.

```python linenums="1" hl_lines="2" title="assert.py"
def foobar(a: str = None):
    if a is not None:
        return f"Hello {a}"

foobar("World")
```

# See also

!!! info
    - [Simple statements — Python documentation](https://docs.python.org/3/reference/simple_stmts.html#the-assert-statement)
    - [CWE-617: Reachable Assertion](https://cwe.mitre.org/data/definitions/617.html)
    - [CWE-703: Improper Check or Handling of Exceptional Conditions](https://cwe.mitre.org/data/definitions/703.html)

_New in version 0.3.8_

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class Assert(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_check",
            description=__doc__,
            cwe_id=703,
            message="Assert statements are disabled when optimizations are "
            "enabled.",
        )

    def analyze_assert(self, context: dict) -> Result:
        return Result(
            rule_id=self.id,
            artifact=context["artifact"],
            location=Location(context["node"]),
        )
