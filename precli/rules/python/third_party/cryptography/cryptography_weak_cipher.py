# Copyright 2023 Secure Saurce LLC
r"""
=======================================================================
Use of a Broken or Risky Cryptographic Algorithm in Cryptography Module
=======================================================================

Using weak ciphers for cryptographic algorithms can pose significant security
risks, and it's generally advised to avoid them in favor of stronger, more
secure algorithms. Here's some guidance that advises against using weak
ciphers like ARC4, IDEA, and Blowfish:

1. **NIST Recommendations**: The National Institute of Standards and
Technology (NIST) is a widely recognized authority on cryptographic standards.
NIST advises against using weak ciphers in their Special Publication
800-175B: "Guide to Secure Web Services." They recommend the use of stronger
ciphers like AES (Advanced Encryption Standard) and SHA-256 for cryptographic
purposes.

2. **IETF Standards**: The Internet Engineering Task Force (IETF) publishes
standards and guidelines for secure network communication. IETF has deprecated
or discouraged the use of weak ciphers in various RFCs (Request for
Comments). For example, RFC 7465 advises against using SSLv3 and RC4 due to
their vulnerabilities.

3. **OWASP Guidelines**: The Open Web Application Security Project (OWASP)
provides guidelines for secure web applications. Their guidance explicitly
recommends avoiding weak ciphers, including ARC4, IDEA, and Blowfish, due to
known security weaknesses.

4. **PCI DSS Compliance**: The Payment Card Industry Data Security Standard
(PCI DSS) mandates the use of strong cryptographic algorithms. Using weak
ciphers is discouraged and can lead to non-compliance with PCI DSS
requirements.

5. **Industry Best Practices**: Various cybersecurity experts and
organizations, such as SANS Institute, CERT/CC (Computer Emergency Response
Team Coordination Center), and security vendors, provide guidance on best
practices for cryptographic algorithms. These resources typically recommend
avoiding the use of weak ciphers.

6. **Security Research**: Academic papers and security research often
highlight the vulnerabilities of weak ciphers like ARC4, IDEA, and Blowfish.
These findings reinforce the importance of avoiding these ciphers in
security-critical applications.

7. **Compliance Standards**: Depending on your industry and location,
there may be specific regulatory requirements that prohibit the use of
weak ciphers. Ensure compliance with applicable regulations by using strong,
approved cryptographic algorithms.

8. **TLS/SSL Configuration**: If you are configuring web servers or other
network services that use TLS/SSL for encryption, it's essential to configure
your server to support only strong ciphersuites and protocols. Weak ciphers,
such as RC4, have known vulnerabilities and should be disabled.

In summary, there is a consensus among reputable standards organizations,
industry experts, and security professionals that weak ciphers like ARC4,
IDEA, and Blowfish should be avoided due to their known vulnerabilities and
weaknesses. Instead, it is advisable to use stronger, more secure
cryptographic algorithms and adhere to industry best practices and regulatory
requirements for encryption and security.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 8,9

    import os

    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms


    key = os.urandom(32)
    algorithm = algorithms.ARC4(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message")

-----------
Remediation
-----------

It is advisable to use stronger, more secure cryptographic algorithms such as
AES.

.. code-block:: python
   :linenos:
   :emphasize-lines: 10,11

    import os

    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms
    from cryptography.hazmat.primitives.ciphers import modes


    key = os.urandom(32)
    iv = os.urandom(16)
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()

.. seealso::

 - `Use of a Broken or Risky Cryptographic Algorithm in Cryptography Module <https://docs.securesauce.dev/rules/PRE0501>`_
 - `Symmetric encryption — Cryptography documentation <https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#weak-ciphers>`_
 - `CWE-327: Use of a Broken or Risky Cryptographic Algorithm <https://cwe.mitre.org/data/definitions/327.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


WEAK_CIPHER = [
    "cryptography.hazmat.primitives.ciphers.algorithms.ARC4",
    "cryptography.hazmat.primitives.ciphers.algorithms.Blowfish",
    "cryptography.hazmat.primitives.ciphers.algorithms.IDEA",
]


class CryptographyWeakCipher(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="use_of_a_broken_or_risky_cryptographic_algorithm",
            full_descr=__doc__,
            cwe_id=327,
            message="Weak ciphers like {} should be avoided due to their "
            "known vulnerabilities and weaknesses.",
            targets=("call"),
            wildcards={
                "cryptography.hazmat.primitives.ciphers.algorithms.*": [
                    "ARC4",
                    "Blowfish",
                    "IDEA",
                ],
                "cryptography.hazmat.primitives.ciphers.*": [
                    "Cipher",
                    "algorithms.ARC4",
                    "algorithms.Blowfish",
                    "algorithms.IDEA",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in WEAK_CIPHER:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.identifier_node),
                description="It is advisable to use a stronger, more "
                "secure cryptographic algorithm like AES.",
                inserted_content="AES",
            )
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.identifier_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name),
                fixes=fixes,
            )
        elif call.name_qualified in [
            "cryptography.hazmat.primitives.ciphers.Cipher",
        ]:
            arg0 = call.get_argument(position=0, name="algorithm")
            algorithm = arg0.value
            arg1 = call.get_argument(position=1, name="mode")

            if arg1.node is not None:
                loc_node = arg1.node
                content = "CBC(os.urandom(16))"
            else:
                loc_node = arg0.node
                content = f"{arg0.node.text.decode()}, CBC(os.urandom(16))"

            if algorithm in WEAK_CIPHER:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=loc_node),
                    description="The AES cipher is a block cipher requiring "
                    "a mode such as CBC to be specified.",
                    inserted_content=content,
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=arg0.identifier_node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format(algorithm),
                    fixes=fixes,
                )
