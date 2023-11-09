# Copyright 2023 Secure Saurce LLC
r"""
===============================================================
Use of a Risky Cryptographic Cipher Mode in Cryptography Module
===============================================================

Using weak cipher modes, such as Electronic Codebook (ECB), for cryptographic
algorithms is generally discouraged due to significant security vulnerabilities
associated with them.

ECB mode is highly vulnerable to various attacks, primarily because it
encrypts each block of plaintext independently. As a result, identical
plaintext blocks will produce identical ciphertext blocks. This can leak
information about the underlying data, and patterns within the data may be
discernible, making it easier for attackers to exploit these patterns.

ECB mode also does not provide diffusion, which means that changes in the
plaintext have a limited impact on the ciphertext. This lack of diffusion
makes it easier for attackers to manipulate or infer information from the
ciphertext.

Because of the determinism in ECB mode, it is susceptible to chosen-plaintext
attacks, where an attacker can manipulate the input data to reveal patterns
or vulnerabilities in the encryption.

ECB mode is designed for block ciphers, which means it can only encrypt data
in fixed-size blocks. If you need to encrypt larger messages, you would have
to implement additional techniques (e.g., chaining modes) which can be
complex and prone to implementation errors.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 10

    import os

    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.ciphers import modes


    key = os.urandom(32)
    algorithm = algorithms.AES(key)
    mode = modes.ECB()
    cipher = Cipher(algorithm, mode=mode)
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()

-----------
Remediation
-----------

It is advisable to use a secure cryptographic algorithms such as CBC.

.. code-block:: python
   :linenos:
   :emphasize-lines: 9,11

    import os

    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.ciphers import modes


    key = os.urandom(32)
    iv = os.urandom(16)
    algorithm = algorithms.AES(key)
    mode = modes.CBC(iv)
    cipher = Cipher(algorithm, mode=mode)
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()

.. seealso::

 - `Use of a Risky Cryptographic Cipher Mode in Cryptography Module <https://docs.securesauce.dev/rules/PRE0502>`_
 - `Symmetric encryption — Cryptography documentation <https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#insecure-modes>`_
 - `CWE-327: Use of a Broken or Risky Cryptographic Algorithm <https://cwe.mitre.org/data/definitions/327.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class CryptographyWeakCipherMode(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="use_of_risky_cryptographic_cipher_mode",
            full_descr=__doc__,
            cwe_id=327,
            message="ECB mode is highly vulnerable to various attacks.",
            targets=("call"),
            wildcards={
                "cryptography.hazmat.primitives.ciphers.modes.*": [
                    "ECB",
                ],
                "cryptography.hazmat.primitives.ciphers.*": [
                    "modes.ECB",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "cryptography.hazmat.primitives.ciphers.modes.ECB",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.identifier_node,
                ),
                level=Level.ERROR,
            )
