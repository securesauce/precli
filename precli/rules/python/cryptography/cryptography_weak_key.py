# Copyright 2023 Secure Saurce LLC
r"""
=====================================================================
Inadequate Encryption Strength Using Weak Keys in Cryptography Module
=====================================================================

Using weak key sizes for cryptographic algorithms like RSA, DSA, and EC
(Elliptic Curve) can compromise the security of your encryption and digital
signatures. Here's a brief overview of the risks associated with weak key
sizes for these algorithms:

RSA (Rivest-Shamir-Adleman):
RSA is widely used for both encryption and digital signatures. Weak key sizes
in RSA can be vulnerable to factorization attacks, such as the famous RSA-129
challenge, which was factored in 1994 after 17 years of effort. Using small
key sizes makes it easier for attackers to factor the modulus and recover
the private key.

It's generally recommended to use RSA key sizes of 2048 bits or more for
security in the present day, with 3072 bits or higher being increasingly
preferred for long-term security.

DSA (Digital Signature Algorithm):
DSA is used for digital signatures and relies on the discrete logarithm
problem. Using weak key sizes in DSA can make it susceptible to attacks that
involve solving the discrete logarithm problem, like the GNFS (General
Number Field Sieve) algorithm.

For DSA, key sizes of 2048 bits or more are recommended for modern security.
Note that DSA is not as commonly used as RSA or ECC for new applications, and
ECDSA (Elliptic Curve Digital Signature Algorithm) is often preferred due to
its efficiency and strong security properties.

EC (Elliptic Curve):
Elliptic Curve cryptography provides strong security with relatively small
key sizes compared to RSA and DSA. However, even in the case of EC, using
weak curve parameters or small key sizes can expose you to vulnerabilities.
The strength of an EC key depends on the curve's properties and the size of
the prime used.

Recommended EC key sizes depend on the curve you select, but for modern
applications, curves like NIST P-256 (secp256r1) with a 256-bit key size
are considered secure. Larger curves, like NIST P-384 or P-521, can provide
even higher security margins.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from cryptography.hazmat.primitives.asymmetric import rsa


    rsa.generate_private_key(key_size=1024)

-----------
Remediation
-----------

Its recommended to increase the key size to at least 2048 for DSA and RSA
algorithms.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from cryptography.hazmat.primitives.asymmetric import rsa


    rsa.generate_private_key(65537, key_size=3072)

.. seealso::

 - `Inadequate Encryption Strength Using Weak Keys in Cryptography Module <https://docs.securesauce.dev/rules/PRE0505>`_
 - `Asymmetric algorithms — Cryptography documentation <https://cryptography.io/en/latest/hazmat/primitives/asymmetric/>`_
 - `CWE-326: Inadequate Encryption Strength <https://cwe.mitre.org/data/definitions/326.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


CURVE_SIZES = {
    "cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP256R1": 256,
    "cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP384R1": 384,
    "cryptography.hazmat.primitives.asymmetric.ec.BrainpoolP512R1": 512,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP192R1": 192,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP224R1": 224,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP256K1": 256,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP256R1": 256,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP384R1": 384,
    "cryptography.hazmat.primitives.asymmetric.ec.SECP521R1": 521,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT163K1": 163,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT163R2": 163,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT233K1": 233,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT233R1": 233,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT283K1": 283,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT283R1": 283,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT409K1": 409,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT409R1": 409,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT571K1": 571,
    "cryptography.hazmat.primitives.asymmetric.ec.SECT571R1": 570,
}


class CryptographyWeakKey(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            full_descr=__doc__,
            cwe_id=326,
            message="Using {} key sizes less than {} bits is considered "
            "vulnerable to attacks.",
            targets=("call"),
            wildcards={
                "cryptography.hazmat.primitives.asymmetric.*": [
                    "dsa",
                    "rsa",
                    "ec",
                ],
                "cryptography.hazmat.primitives.*": [
                    "asymmetric.dsa",
                    "asymmetric.rsa",
                    "asymmetric.ec",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "cryptography.hazmat.primitives.asymmetric.dsa."
            "generate_private_key",
            "cryptography.hazmat.primitives.asymmetric.dsa."
            "generate_parameters",
        ]:
            argument = call.get_argument(position=0, name="key_size")
            key_size = argument.value

            if key_size < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Use a minimum key size of 2048 for DSA keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.node,
                    ),
                    level=Level.ERROR if key_size <= 1024 else Level.WARNING,
                    message=self.message.format("DSA", 2048),
                    fixes=fixes,
                )
        elif call.name_qualified in [
            "cryptography.hazmat.primitives.asymmetric.rsa."
            "generate_private_key",
        ]:
            argument = call.get_argument(position=1, name="key_size")
            key_size = argument.value

            if key_size < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Use a minimum key size of 2048 for RSA keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.node,
                    ),
                    level=Level.ERROR if key_size <= 1024 else Level.WARNING,
                    message=self.message.format("RSA", 2048),
                    fixes=fixes,
                )
        elif call.name_qualified in [
            "cryptography.hazmat.primitives.asymmetric.ec."
            "generate_private_key",
        ]:
            argument = call.get_argument(position=0, name="curve")
            curve = argument.value
            key_size = CURVE_SIZES[curve] if curve in CURVE_SIZES else 224

            if key_size < 224:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use a curve with a minimum size of 224 bits.",
                    inserted_content="SECP256R1",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR if key_size < 160 else Level.WARNING,
                    message=self.message.format("EC", 224),
                    fixes=fixes,
                )
        elif call.name_qualified in [
            "cryptography.hazmat.primitives.asymmetric.ec."
            "derive_private_key",
        ]:
            argument = call.get_argument(position=1, name="curve")
            curve = argument.value
            key_size = CURVE_SIZES[curve] if curve in CURVE_SIZES else 224

            if key_size < 224:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use a curve with a minimum size of 224 bits.",
                    inserted_content="SECP256R1",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR if key_size < 160 else Level.WARNING,
                    message=self.message.format("EC", 224),
                    fixes=fixes,
                )
