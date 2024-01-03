# Copyright 2024 Secure Saurce LLC
r"""
====================================================================
Use of a Broken or Risky Cryptographic Algorithm in X Crypto Package
====================================================================

Using weak ciphers for cryptographic algorithms can pose significant security
risks, and it's generally advised to avoid them in favor of stronger, more
secure algorithms. Here's some guidance that advises against using weak
ciphers like Blowfish, CAST5, TEA/XTEA, and Twofish:

Blowfish: Developed in 1993, Blowfish is a block cipher known for its
simplicity. However, its small block size of 64 bits makes it susceptible to
birthday attacks in modern contexts. This vulnerability is significant when
encrypting large amounts of data, which is common in current applications.

CAST5 (CAST-128): CAST5, a symmetric encryption algorithm, suffers from
similar issues as Blowfish due to its 64-bit block size. While it was
considered secure for its time, modern applications typically require
algorithms with larger block sizes for enhanced security.

TEA/XTEA: The Tiny Encryption Algorithm (TEA) and its successor, eXtended
TEA (XTEA), are lightweight block ciphers. They are notable for their
simplicity and ease of implementation but have known vulnerabilities,
including susceptibility to differential cryptanalysis. These weaknesses
make them less suitable for applications where strong security is a priority.

Twofish: As a finalist in the Advanced Encryption Standard (AES) competition,
Twofish is a respected algorithm. However, it was not selected as the
standard, and over time, AES has become the more tested and trusted choice
in most cryptographic applications.

In summary, there is a consensus among reputable standards organizations,
industry experts, and security professionals that weak ciphers like Blowfish,
CAST5, TEA/XTEA, and Twofish should be avoided due to their known
vulnerabilities and weaknesses. Instead, it is advisable to use stronger,
more secure cryptographic algorithms and adhere to industry best practices
and regulatory requirements for encryption and security.

-------
Example
-------

.. code-block:: go
   :linenos:
   :emphasize-lines: 11

    package main

    import (
        "log"
        "golang.org/x/crypto/twofish"
    )

    func main() {
        key := []byte("examplekey123456")

        _, err := twofish.NewCipher(key)
        if err != nil {
            log.Fatalf("Failed to create cipher: %v", err)
        }
    }

-----------
Remediation
-----------

It is advisable to use stronger, more secure cryptographic algorithms such as
AES.

.. code-block:: go
   :linenos:
   :emphasize-lines: 5,11

    package main

    import (
        "log"
        "crypto/aes"
    )

    func main() {
        key := []byte("examplekey123456")

        _, err := aes.NewCipher(key)
        if err != nil {
            log.Fatalf("Failed to create cipher: %v", err)
        }
    }

.. seealso::

 - `Use of a Broken or Risky Cryptographic Algorithm in Crypto Package <https://docs.securesauce.dev/rules/GO502>`_
 - `blowfish package - golang.org_x_crypto_twofish - Go Packages <https://pkg.go.dev/golang.org/x/crypto/blowfish>`_
 - `cast5 package - golang.org_x_crypto_twofish - Go Packages <https://pkg.go.dev/golang.org/x/crypto/cast5>`_
 - `tea package - golang.org_x_crypto_twofish - Go Packages <https://pkg.go.dev/golang.org/x/crypto/tea>`_
 - `twofish package - golang.org_x_crypto_twofish - Go Packages <https://pkg.go.dev/golang.org/x/crypto/twofish>`_
 - `xtea package - golang.org_x_crypto_twofish - Go Packages <https://pkg.go.dev/golang.org/x/crypto/xtea>`_
 - `CWE-327: Use of a Broken or Risky Cryptographic Algorithm <https://cwe.mitre.org/data/definitions/327.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class WeakCipher(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="use_of_a_broken_or_risky_cryptographic_algorithm",
            full_descr=__doc__,
            cwe_id=327,
            message="Weak ciphers like {} should be avoided due to their "
            "known vulnerabilities and weaknesses.",
            targets=("call"),
            wildcards={},
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "golang.org/x/crypto/blowfish.NewCipher",
            "golang.org/x/crypto/blowfish.NewSaltedCipher",
            "golang.org/x/crypto/cast5.NewCipher",
            "golang.org/x/crypto/tea.NewCipher",
            "golang.org/x/crypto/tea.NewCipherWithRounds",
            "golang.org/x/crypto/twofish.NewCipher",
            "golang.org/x/crypto/xtea.NewCipher",
        ]:
            # TODO: Need to remove arguments for NewSaltedCipher and
            # NewCipherWithRounds
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="It is advisable to use a stronger, more "
                "secure cryptographic algorithm like AES.",
                inserted_content="aes.NewCipher",
            )
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name),
                fixes=fixes,
            )
