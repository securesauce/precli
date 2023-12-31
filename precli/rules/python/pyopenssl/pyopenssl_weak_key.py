# Copyright 2023 Secure Saurce LLC
r"""
==================================================================
Inadequate Encryption Strength Using Weak Keys in PyOpenSSL Module
==================================================================

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

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from OpenSSL import crypto


    crypto.PKey().generate_key(type=crypto.TYPE_DSA, bits=1024)

-----------
Remediation
-----------

Its recommended to increase the key size to at least 2048 for DSA and RSA
algorithms.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from OpenSSL import crypto


    crypto.PKey().generate_key(type=crypto.TYPE_DSA, bits=2048)

.. seealso::

 - `Inadequate Encryption Strength Using Weak Keys in PyOpenSSL Module <https://docs.securesauce.dev/rules/PRE0520>`_
 - `crypto — Generic cryptographic module — pyOpenSSL documentation <https://www.pyopenssl.org/en/latest/api/crypto.html#pkey-objects>`_
 - `CWE-326: Inadequate Encryption Strength <https://cwe.mitre.org/data/definitions/326.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PyopensslWeakKey(Rule):
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
                "OpenSSL.crypto.*": [
                    "PKey",
                    "TYPE_DSA",
                ],
                "OpenSSL.*": [
                    "crypto.PKey",
                    "crypto.TYPE_DSA",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified == "OpenSSL.crypto.PKey.generate_key":
            arg0 = call.get_argument(position=0, name="type")
            key_type = arg0.value

            if key_type == "OpenSSL.crypto.TYPE_DSA":
                key = "DSA"
            elif key_type == "OpenSSL.crypto.TYPE_RSA":
                key = "RSA"

            arg1 = call.get_argument(position=1, name="bits")
            bits = arg1.value

            if key in ["DSA", "RSA"] and bits < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=arg1.node),
                    description=f"Use a minimum key size of 2048 for "
                    f"{key_type} keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=arg1.node,
                    ),
                    level=Level.ERROR if bits <= 1024 else Level.WARNING,
                    message=self.message.format(key_type, 2048),
                    fixes=fixes,
                )
