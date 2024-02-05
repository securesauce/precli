# Copyright 2024 Secure Saurce LLC
r"""
=========================================
Reversible One Way Hash in Hashlib Module
=========================================

The Python module ``hashlib`` provides a number of functions for hashing data.
However, some of the hash algorithms supported by hashlib are insecure and
should not be used. These insecure hash algorithms include ``MD4``, ``MD5``,
``RIPEMD-160`` and ``SHA-1``.

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

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import hashlib


    hash = hashlib.md5(b"Nobody inspects the spammish repetition")
    hash.hexdigest()

-----------
Remediation
-----------

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, ``SHA256`` or ``SHA512``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import hashlib


    hash = hashlib.sha256(b"Nobody inspects the spammish repetition")
    hash.hexdigest()

If an insecure hash such as MD5 must be used and not in within a security
context, then set the keyword-only argument ``usedforsecurity`` in the hashes
constructor.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import hashlib


    hash = hashlib.md5(b"Non-security related text", usedforsecurity=False)
    hash.hexdigest()

.. seealso::

 - `hashlib — Secure hashes and message digests <https://docs.python.org/3/library/hashlib.html>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.argument import Argument
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


WEAK_HASHES = ("md4", "md5", "ripemd160", "sha", "sha1")


class HashlibWeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe_id=328,
            message="Use of weak hash function '{}' does not meet security "
            "expectations.",
            targets=("call"),
            wildcards={
                "hashlib.*": [
                    "md4",
                    "md5",
                    "ripemd160",
                    "sha",
                    "sha1",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "hashlib.md4",
            "hashlib.md5",
            "hashlib.ripemd160",
            "hashlib.sha",
            "hashlib.sha1",
        ]:
            """
            hashlib.md4(string=b'', *, usedforsecurity=True)
            hashlib.md5(string=b'', *, usedforsecurity=True)
            hashlib.ripemd160(string=b'', *, usedforsecurity=True)
            hashlib.sha(string=b'', *, usedforsecurity=True)
            hashlib.sha1(string=b'', *, usedforsecurity=True)
            """
            used_for_security = call.get_argument(
                name="usedforsecurity", default=Argument(None, True)
            ).value

            if used_for_security is True:
                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.function_node),
                    level=Level.ERROR,
                    message=self.message.format(call.name_qualified),
                )
        elif call.name_qualified in ["hashlib.pbkdf2_hmac"]:
            """
            hashlib.pbkdf2_hmac(
                hash_name,
                password,
                salt,
                iterations,
                dklen=None
            )
            """
            hash_name = call.get_argument(position=0, name="hash_name").value

            if isinstance(hash_name, str) and hash_name.lower() in WEAK_HASHES:
                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.function_node),
                    level=Level.ERROR,
                    message=self.message.format(hash_name),
                )
        elif call.name_qualified in ["hashlib.new"]:
            """
            hashlib.new(name, data=b'', **kwargs)
            """
            name = call.get_argument(position=0, name="name").value

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                used_for_security = call.get_argument(
                    name="usedforsecurity", default=Argument(None, True)
                ).value

                if used_for_security is True:
                    return Result(
                        rule_id=self.id,
                        artifact=context["artifact"],
                        location=Location(node=call.function_node),
                        level=Level.ERROR,
                        message=self.message.format(name),
                    )
