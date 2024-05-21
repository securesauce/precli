# Copyright 2024 Secure Sauce LLC
r"""
# Insufficient `hmac` Key Size

This rule identifies instances where the key provided to `hmac.digest()` or
`hmac.new()` is considered too small relative to the digest algorithm's
digest size. Using keys that are too short can compromise the integrity and
security of the HMAC (Hash-based Message Authentication Code), making it less
resistant to brute-force attacks.

HMAC is a mechanism for message authentication using cryptographic hash
functions. The security of an HMAC depends significantly on the secret key's
strength. A key that is shorter than the hash function's output size
(digest size) can reduce the HMAC's effectiveness, making it more vulnerable
to attacks. It is essential to use keys of adequate length to maintain the
expected level of security, especially against brute-force attacks.

Ensure that the key length used with `hmac.digest()` or `hmac.new()` is at
least equal to the digest size of the hash function being used. This
compliance requirement helps maintain the cryptographic strength of the
HMAC and protects the integrity of the message authentication process.

## Example

```python
import hashlib
import hmac
import secrets


key = secrets.token_bytes(nbytes=32)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_384)
```

## Remediation

Adjust the key size to be at least the size of the digest.

```python
import hashlib
import hmac
import secrets


key = secrets.token_bytes(nbytes=48)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_384)
```

## See also

- [hmac — Keyed-Hashing for Message Authentication](https://docs.python.org/3/library/hmac.html)
- [secrets — Generate secure random numbers for managing secrets](https://docs.python.org/3/library/secrets.html#generating-tokens)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

_New in version 0.4.3_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


HASH_NAME_SIZES = {
    "blake2s": 32,
    "blake2b": 64,
    "sha224": 28,
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
    "sha3_224": 28,
    "sha3_256": 32,
    "sha3_384": 48,
    "sha3_512": 64,
    "sha512_224": 28,
    "sha512_256": 32,
    "shake_128": 0,  # TODO
    "shake_256": 0,  # TODO
    "sm3": 32,
}

HASHLIB_SIZES = {
    "hashlib.blake2s": 32,
    "hashlib.blake2b": 64,
    "hashlib.sha224": 28,
    "hashlib.sha256": 32,
    "hashlib.sha384": 48,
    "hashlib.sha512": 64,
    "hashlib.sha3_224": 28,
    "hashlib.sha3_256": 32,
    "hashlib.sha3_384": 48,
    "hashlib.sha3_512": 64,
    "hashlib.sha512_224": 28,
    "hashlib.sha512_256": 32,
    "hashlib.shake_128": 0,  # TODO
    "hashlib.shake_256": 0,  # TODO
    "hashlib.sm3": 32,
}


class HmacWeakKey(Rule):
    def __init__(self, id: str) -> None:
        super().__init__(
            id=id,
            name="insufficient_key_size",
            description=__doc__,
            cwe_id=326,
            message="The given key is only '{0}' bytes which is insufficient "
            "for the '{2}' algorithm.",
            wildcards={
                "hashlib.*": [
                    "blake2s",
                    "blake2b",
                    "sha224",
                    "sha256",
                    "sha384",
                    "sha512",
                    "sha3_224",
                    "sha3_256",
                    "sha3_384",
                    "sha3_512",
                    "sha512_224",
                    "sha512_256",
                    "shake_128",
                    "shake_256",
                    "sm3",
                ],
                "hmac.*": [
                    "new",
                    "digest",
                ],
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in ("hmac.new", "hmac.digest"):
            return

        # new(key, msg=None, digestmod='')
        #    Create a new hashing object and return it.
        #
        #    key: bytes or buffer, The starting key for the hash.
        #    msg: bytes or buffer, Initial input for the hash, or None.
        #    digestmod: A hash name suitable for hashlib.new(). *OR*
        #               A hashlib constructor returning a new hash object.
        #               *OR*
        #               A module supporting PEP 247.
        #
        #               Required as of 3.8, despite its position after the
        #               optional
        #               msg argument.  Passing it as a keyword argument is
        #               recommended, though not required for legacy API
        #               reasons.
        #
        #    You can now feed arbitrary bytes into the object using its
        #    update() method, and can ask for the hash value at any time
        #    by calling its digest() or hexdigest() methods.
        #
        # digest(key, msg, digest)
        #    Fast inline implementation of HMAC.
        #
        #    key: bytes or buffer, The key for the keyed hash object.
        #    msg: bytes or buffer, Input message.
        #    digest: A hash name suitable for hashlib.new() for best
        #            performance. *OR*
        #            A hashlib constructor returning a new hash object.
        #            *OR*
        #            A module supporting PEP 247.
        if call.name_qualified == "hmac.new":
            arg_name = "digestmod"
        else:
            arg_name = "digest"

        arg0 = call.get_argument(position=0, name="key")
        if arg0.value in (
            "secrets.token_bytes",
            "secrets.token_hex",
            "secrets.token_urlsafe",
        ):
            symbol = context["symtab"].get(arg0.node.text.decode())
            lastcall = symbol.call_history[-1]
            nbytes = lastcall.get_argument(position=0, name="nbytes").value
            key_size = nbytes if nbytes is not None else 32
        elif arg0.is_str:
            key_size = len(arg0.value_str)
        else:
            return

        arg2 = call.get_argument(position=2, name=arg_name)
        if arg2.value in HASHLIB_SIZES:
            digest = arg2.value
            min_digest_size = HASHLIB_SIZES.get(digest)
        elif arg2.is_str and arg2.value_str in HASH_NAME_SIZES:
            digest = arg2.value_str
            min_digest_size = HASH_NAME_SIZES.get(digest)
        else:
            return

        if key_size >= min_digest_size:
            return

        return Result(
            rule_id=self.id,
            location=Location(node=arg0.node),
            message=self.message.format(key_size, min_digest_size, digest),
        )
