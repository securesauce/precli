# Copyright 2023 Secure Saurce LLC
r"""
=================================================================
Inadequate Encryption Strength Using Weak Keys in M2Crypto Module
=================================================================

Using weak key sizes for cryptographic algorithms like RSA and DSA can
compromise the security of your encryption and digital signatures. Here's
a brief overview of the risks associated with weak key sizes for these
algorithms:

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

    from M2Crypto import RSA


    new_key = RSA.gen_key(1024, 65537)

-----------
Remediation
-----------

Its recommended to increase the key size to at least 2048 for DSA and RSA
algorithms.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from M2Crypto import RSA


    new_key = RSA.gen_key(2048, 65537)

.. seealso::

 - `Inadequate Encryption Strength Using Weak Keys in M2Crypto Module <https://docs.securesauce.dev/rules/PRE0509>`_
 - `m2crypto _ m2crypto · GitLab <https://gitlab.com/m2crypto/m2crypto>`_
 - `CWE-326: Inadequate Encryption Strength <https://cwe.mitre.org/data/definitions/326.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
import re

from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class M2CryptoWeakKey(Rule):
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
                "M2Crypto.RSA.*": [
                    "gen_key",
                ],
                "M2Crypto.DSA.*": [
                    "gen_params",
                ],
                "M2Crypto.*": [
                    "RSA.gen_key",
                    "DSA.gen_params",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified == "M2Crypto.RSA.gen_key":
            arg0 = call.get_argument(position=0, name="bits")
            bits = arg0.value

            if bits < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=arg0.node),
                    description="Use a minimum key size of 2048 for RSA keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=arg0.node,
                    ),
                    level=Level.ERROR if bits <= 1024 else Level.WARNING,
                    message=self.message.format("RSA", 2048),
                    fixes=fixes,
                )
        elif call.name_qualified == "M2Crypto.DSA.gen_params":
            arg0 = call.get_argument(position=0, name="bits")
            bits = arg0.value

            if bits < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=arg0.node),
                    description="Use a minimum key size of 2048 for DSA keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=arg0.node,
                    ),
                    level=Level.ERROR if bits <= 1024 else Level.WARNING,
                    message=self.message.format("DSA", 2048),
                    fixes=fixes,
                )
        elif call.name_qualified == "M2Crypto.EC.gen_params":
            arg0 = call.get_argument(position=0, name="curve")
            curve = arg0.value
            result = re.search(r"NID_sec[p|t](\d{3})(?:r1|r2|k1){1}", curve)
            if not result:
                result = re.search(r"NID_prime(\d{3})v[1|2|3]", curve)
            if not result:
                result = re.search(
                    r"NID_c2[p|t]nb(\d{3})(?:v1|v2|v3|w1|r1){1}", curve
                )
            key_size = int(result.group(1)) if result else 224

            if key_size < 224:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=arg0.identifier_node),
                    description="Use a curve with a minimum size of 224 bits.",
                    inserted_content="NID_secp256k1",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=arg0.identifier_node,
                    ),
                    level=Level.ERROR if key_size < 160 else Level.WARNING,
                    message=self.message.format("EC", 224),
                    fixes=fixes,
                )
