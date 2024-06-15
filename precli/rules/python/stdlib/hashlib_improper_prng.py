# Copyright 2024 Secure Sauce LLC
r"""
# Improper Randomness for Cryptographic `hashlib` Functions

This rule detects the use of non-cryptographically secure randomness sources,
such as Python's `random()` function, as inputs to cryptographic functions
like `hashlib.scrypt()`. Using non-secure randomness sources can weaken the
cryptographic strength of functions that rely on unpredictability for security.

Cryptographic functions, including key generation, encryption, and hashing,
require a source of randomness that is unpredictable and secure against
attack. The standard `random()` function in Python is designed for statistical
modeling and simulations, not for security purposes, as it generates
predictable sequences that can be reproduced if the seed value is known.
Using `random()` for cryptographic purposes, such as generating salts or keys,
compromises security by making the output potentially predictable to attackers.

Ensure all cryptographic operations utilize a cryptographically secure source
of randomness. Python provides the `secrets` module for generating secure
random numbers suitable for security-sensitive applications, including key
generation and creating salts for hashing functions.

## Example

```python
import hashlib
import random


password = b"my_secure_password"
salt = random.randbytes(16)
hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
```

## Remediation

For security or cryptographic uses use a secure pseudo-random generator such
as `os.urandom()` or `secrets.token_bytes()`.

```python
import hashlib
import os


password = b"my_secure_password"
salt = os.urandom(16)
hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
```

## See also

- [random — Generate pseudo-random numbers](https://docs.python.org/3/library/random.html#random.randbytes)
- [hashlib — Secure hashes and message digests](https://docs.python.org/3/library/hashlib.html)
- [ssl — TLS_SSL wrapper for socket objects](https://docs.python.org/3/library/ssl.html#ssl.RAND_bytes)
- [CWE-330: Use of Insufficiently Random Values](https://cwe.mitre.org/data/definitions/330.html)

_New in version 0.4.3_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class HashlibImproperPrng(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_random",
            description=__doc__,
            cwe_id=330,
            message="The '{0}' pseudo-random generator should not be used for "
            "security purposes.",
            wildcards={
                "hashlib.*": [
                    "blake2b",
                    "blake2s",
                    "pbkdf2_hmac",
                    "scrypt",
                ],
                "random.*": [
                    "randbytes",
                ],
                "ssl.*": [
                    "RAND_bytes",
                ],
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in (
            "hashlib.blake2b",
            "hashlib.blake2s",
            "hashlib.pbkdf2_hmac",
            "hashlib.scrypt",
        ):
            return

        # hashlib.blake2b(data=b'', *, digest_size=64, key=b'', salt=b'',
        # person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0,
        # node_depth=0, inner_size=0, last_node=False, usedforsecurity=True)

        # hashlib.blake2s(data=b'', *, digest_size=32, key=b'', salt=b'',
        # person=b'', fanout=1, depth=1, leaf_size=0, node_offset=0,
        # node_depth=0, inner_size=0, last_node=False, usedforsecurity=True)

        # hashlib.pbkdf2_hmac(
        #   hash_name, password, salt, iterations, dklen=None
        # )

        # hashlib.scrypt(password, *, salt, n, r, p, maxmem=0, dklen=64)
        argument = None
        if call.name_qualified == "hashlib.pbkdf2_hmac":
            argument = call.get_argument(position=2, name="salt")
        elif call.name_qualified in (
            "hashlib.blake2b",
            "hashlib.blake2s",
            "hashlib.scrypt",
        ):
            argument = call.get_argument(name="salt")

        if not argument or argument.value not in (
            "random.randbytes",
            "ssl.RAND_bytes",
        ):
            return

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=argument.node),
            description="The salt should be 16 or more bytes from a proper "
            "pseudo-random source such as `os.urandom()`.",
            inserted_content="os.urandom(16)",
        )

        return Result(
            rule_id=self.id,
            location=Location(node=argument.node),
            message=self.message.format(argument.value),
            fixes=fixes,
        )
