# Copyright 2024 Secure Sauce LLC
r"""
# Insufficient Token Length

Tokens are often used as security-critical elements, such as for
authentication, session management, or as part of cryptographic operations.
The strength of a token is significantly influenced by its length and the
randomness of its generation. Tokens with insufficient byte lengths lack
the necessary entropy to withstand brute-force attacks, leading to a potential
compromise of the system's security integrity.

All calls to `secrets.token_bytes()`, `secrets.token_hex()`, and
`secrets.token_urlsafe()` MUST specify a byte size of at least 32.
This requirement ensures that the generated tokens have a strong level of
cryptographic security, reducing the risk of unauthorized access through
token prediction or brute-force attacks.

# Example

```python linenums="1" hl_lines="4" title="secrets_token_bytes.py"
import secrets


token = secrets.token_bytes(4)
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/secrets/examples/secrets_token_bytes.py
    ⛔️ Error on line 4 in tests/unit/rules/python/stdlib/secrets/examples/secrets_token_bytes.py
    PY028: Inadequate Encryption Strength
    A token size of '4' is less than the recommended '32' bytes, which can be vulnerable to brute-force attacks.
    ```

# Remediation

Its recommended to increase the token size to at least 32 bytes or leave
the `nbytes` parameter unset or set to None to use a default entropy.

```python linenums="1" hl_lines="4" title="secrets_token_bytes.py"
import secrets


token = secrets.token_bytes()
```

# See also

!!! info
    - [secrets — Generate secure random numbers for managing secrets](https://docs.python.org/3/library/secrets.html#generating-tokens)
    - [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

_New in version 0.3.14_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SecretsWeakToken(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="insufficient_token_length",
            description=__doc__,
            cwe_id=326,
            message="A token size of '{0}' is less than the recommended "
            "'{1}' bytes, which can be vulnerable to brute-force attacks.",
            wildcards={},
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified not in [
            "secrets.token_bytes",
            "secrets.token_hex",
            "secrets.token_urlsafe",
        ]:
            return

        arg = call.get_argument(position=0, name="nbytes")
        nbytes = int(arg.value) if isinstance(arg.value, int) else 32

        if nbytes < 32:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=arg.node),
                description="Pass None or no parameter to use the default "
                "entropy.",
                inserted_content="None",
            )

            return Result(
                rule_id=self.id,
                location=Location(node=arg.node),
                level=Level.ERROR if nbytes < 16 else Level.WARNING,
                message=self.message.format(nbytes, 32),
                fixes=fixes,
            )
