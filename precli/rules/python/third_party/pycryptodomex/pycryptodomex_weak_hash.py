# Copyright 2023 Secure Saurce LLC
r"""
===============================================
Reversible One Way Hash in PyCryptodomex Module
===============================================

The Python module ``pycryptodomex`` provides a number of functions for hashing
data. However, some of the hash algorithms supported by ``pycryptodomex`` are
insecure and should not be used. These insecure hash algorithms include
``MD2``, ``MD4``, ``MD5``, ``RIPEMD`` and ``SHA``.

The MD4 hash algorithm is a cryptographic hash function that was designed in
the late 1980s. MD4 is no longer considered secure, and passwords hashed with
MD4 can be easily cracked by attackers.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and passwords hashed
with MD5 can be easily cracked by attackers.

RIPEMD is a cryptographic hash function that was designed in 1996. It is
considered to be a secure hash function, but it is not as secure as
SHA-256, SHA-384, or SHA-512. In 2017, a collision attack was found for
RIPEMD-160. This means that it is possible to find two different messages
that have the same RIPEMD-160 hash. While this does not mean that RIPEMD-160
is completely insecure, it does mean that it is not as secure as it once was.

The SHA hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and
passwords hashed with SHA-1 can be easily cracked by attackers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from Cryptodome.Hash import MD2


    h = MD2.new()
    h.update(b'Hello')
    print h.hexdigest()

-----------
Remediation
-----------

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, ``SHA256``, ``SHA384``, or ``SHA512``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from Cryptodome.Hash import SHA256


    h = SHA256.new()
    h.update(b'Hello')
    print h.hexdigest()

.. seealso::

 - `Reversible One Way Hash in PyCryptodomex Module <https://docs.securesauce.dev/rules/PRE0514>`_
 - `PyCryptodome <https://www.pycryptodome.org/>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_
.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PycryptodomexWeakHash(Rule):
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
                "Cryptodome.*": [
                    "Hash.MD2.new",
                    "Hash.MD4.new",
                    "Hash.MD5.new",
                    "Hash.RIPEMD.new",
                    "Hash.RIPEMD160.new",
                    "Hash.SHA.new",
                    "Hash.SHA1.new",
                ],
                "Cryptodome.Hash.*": [
                    "MD2.new",
                    "MD4.new",
                    "MD5.new",
                    "RIPEMD.new",
                    "RIPEMD160.new",
                    "SHA.new",
                    "SHA1.new",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "Cryptodome.Hash.MD2.new",
            "Cryptodome.Hash.MD4.new",
            "Cryptodome.Hash.MD5.new",
            "Cryptodome.Hash.RIPEMD.new",
            "Cryptodome.Hash.RIPEMD160.new",
            "Cryptodome.Hash.SHA.new",
            "Cryptodome.Hash.SHA1.new",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
            )
