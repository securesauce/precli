# Copyright 2023 Secure Saurce LLC
r"""
==============================================
Reversible One Way Hash in Cryptography Module
==============================================

The Python module ``cryptography`` provides a number of functions for hashing
data. However, some of the hash algorithms supported by ``cryptography`` are
insecure and should not be used. These insecure hash algorithms include ``MD5``
and ``SHA1``.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and passwords hashed with
MD5 can be easily cracked by attackers.

The SHA-1 hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and
passwords hashed with SHA-1 can be easily cracked by attackers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import cryptography


    cryptography.hazmat.primitives.hashes.MD5()

-----------
Remediation
-----------

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, ``SHA256`` or ``SHA512``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import cryptography


    cryptography.hazmat.primitives.hashes.SHA256()

.. seealso::

 - `Reversible One Way Hash in Cryptography Module <https://docs.securesauce.dev/rules/PY504>`_
 - `Message digests (Hashing) — Cryptography <https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class CryptographyWeakHash(Rule):
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
                "cryptography.hazmat.primitives.hashes.*": [
                    "MD5",
                    "SHA1",
                ],
                "cryptography.hazmat.primitives.*": [
                    "hashes.MD5",
                    "hashes.SHA1",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "cryptography.hazmat.primitives.hashes.MD5",
            "cryptography.hazmat.primitives.hashes.SHA1",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.identifier_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
            )
