# Copyright 2024 Secure Sauce LLC
r"""
# Reversible One Way Hash in `hashlib` Module

The Python module `hashlib` provides a number of functions for hashing data.
However, some of the hash algorithms supported by hashlib are insecure and
should not be used. These insecure hash algorithms include `MD4`, `MD5`,
`RIPEMD-160` and `SHA-1`.

The MD4 hash algorithm is a cryptographic hash function that was designed
in the late 1980s. MD4 is no longer considered secure, and passwords hashed
with MD4 can be easily cracked by attackers.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and passwords hashed
with MD5 can be easily cracked by attackers.

RIPEMD-160 is a cryptographic hash function that was designed in 1996. It is
considered to be a secure hash function, but it is not as secure as SHA-256,
SHA-384, or SHA-512. In 2017, a collision attack was found for RIPEMD-160.
This means that it is possible to find two different messages that have the
same RIPEMD-160 hash. While this does not mean that RIPEMD-160 is completely
insecure, it does mean that it is not as secure as it once was.

The SHA-1 hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and
passwords hashed with SHA-1 can be easily cracked by attackers.

# Example

```python linenums="1" hl_lines="4" title="hashlib_md5.py"
import hashlib


hashlib.md5()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/hashlib/examples/hashlib_md5.py
    ⛔️ Error on line 4 in tests/unit/rules/python/stdlib/hashlib/examples/hashlib_md5.py
    PY004: Use of Weak Hash
    The hash function 'hashlib.md5' is vulnerable to collision and pre-image attacks.
    ```

# Remediation

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, `SHA256` or `SHA512`.

```python linenums="1" hl_lines="4" title="hashlib_md5.py"
import hashlib


hash = hashlib.sha256(b"Nobody inspects the spammish repetition")
hash.hexdigest()
```

If an insecure hash such as MD5 must be used and not in within a security
context, then set the keyword-only argument `usedforsecurity` in the hashes
constructor.

```python linenums="1" hl_lines="4"
import hashlib


hash = hashlib.md5(b"Non-security related text", usedforsecurity=False)
hash.hexdigest()
```

# See also

!!! info
    - [hashlib — Secure hashes and message digests](https://docs.python.org/3/library/hashlib.html)
    - [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
    - [NIST Policy on Hash Functions](https://csrc.nist.gov/projects/hash-functions)

_New in version 0.1.0_

_Changed in version 0.4.1: Added md5-sha1_

"""  # noqa: E501
from precli.core.argument import Argument
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


WEAK_HASHES = ("md4", "md5", "md5-sha1", "ripemd160", "sha", "sha1")
HASHLIB_WEAK_HASHES = (
    "hashlib.md4",
    "hashlib.md5",
    "hashlib.ripemd160",
    "hashlib.sha",
    "hashlib.sha1",
)


class HashlibWeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            description=__doc__,
            cwe_id=328,
            message="The hash function '{0}' is vulnerable to collision and "
            "pre-image attacks.",
            wildcards={
                "hashlib.*": [
                    "md4",
                    "md5",
                    "ripemd160",
                    "sha",
                    "sha1",
                    "pbkdf2_hmac",
                ]
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified in HASHLIB_WEAK_HASHES:
            used_for_security = call.get_argument(
                name="usedforsecurity", default=Argument(None, True)
            ).value

            if used_for_security is True:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=call.identifier_node),
                    description="For cryptographic purposes, use a hash length"
                    " of at least 256-bits with hashes such as SHA-256.",
                    inserted_content="sha256",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(node=call.identifier_node),
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
        elif call.name_qualified in ["hashlib.pbkdf2_hmac"]:
            argument = call.get_argument(position=0, name="hash_name")

            if argument.is_str and argument.value_str.lower() in WEAK_HASHES:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="For cryptographic purposes, use a hash length"
                    " of at least 256-bits with hashes such as SHA-256.",
                    inserted_content='"sha256"',
                )

                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.node),
                    message=self.message.format(argument.value_str),
                    fixes=fixes,
                )
        elif call.name_qualified in ["hashlib.new"]:
            # hashlib.new(name, data=b'', **kwargs)
            argument = call.get_argument(position=0, name="name")

            if argument.is_str and argument.value_str.lower() in WEAK_HASHES:
                used_for_security = call.get_argument(
                    name="usedforsecurity", default=Argument(None, True)
                ).value

                if used_for_security is True:
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=argument.node),
                        description="For cryptographic purposes, use a hash "
                        "length of at least 256-bits with hashes such as "
                        "SHA-256.",
                        inserted_content='"sha256"',
                    )

                    return Result(
                        rule_id=self.id,
                        location=Location(node=argument.node),
                        message=self.message.format(argument.value_str),
                        fixes=fixes,
                    )
