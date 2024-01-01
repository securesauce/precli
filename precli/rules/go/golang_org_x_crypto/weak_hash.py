# Copyright 2023 Secure Saurce LLC
r"""
===========================================
Reversible One Way Hash in X Crypto Package
===========================================

The Go ``golang.org/x/crypto`` package provides a number of functions for
hashing data. However, some of the hash algorithms supported by hashlib are
insecure and should not be used. These insecure hash algorithms include ``MD4``
and ``RIPEMD160``.

The MD4 hash algorithm is a cryptographic hash function that was designed in
the late 1980s. MD4 is no longer considered secure, and passwords hashed with
MD4 can be easily cracked by attackers.

RIPEMD is a cryptographic hash function that was designed in 1996. It is
considered to be a secure hash function, but it is not as secure as
SHA-256, SHA-384, or SHA-512. In 2017, a collision attack was found for
RIPEMD-160. This means that it is possible to find two different messages
that have the same RIPEMD-160 hash. While this does not mean that RIPEMD-160
is completely insecure, it does mean that it is not as secure as it once was.

-------
Example
-------

.. code-block:: go
   :linenos:
   :emphasize-lines: 4,9

    package main

    import (
        "golang.org/x/crypto/md4"
        "fmt"
    )

    func main() {
        h := md4.New()
        h.Write([]byte("hello world\n"))
        fmt.Printf("%x", h.Sum(nil))
    }

-----------
Remediation
-----------

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, ``sha256`` or ``sha512``.

.. code-block:: go
   :linenos:
   :emphasize-lines: 4,9

    package main

    import (
        "crypto/sha256"
        "fmt"
    )

    func main() {
        h := sha256.New()
        h.Write([]byte("hello world\n"))
        fmt.Printf("%x", h.Sum(nil))
    }

.. seealso::

 - `Reversible One Way Hash in X Crypto Package <https://docs.securesauce.dev/rules/GO502>`_
 - `md4 package - golang.org_x_crypto_md4 - Go Packages <https://pkg.go.dev/golang.org/x/crypto/md4>`_
 - `ripemd160 package - golang.org_x_crypto_ripemd160 - Go Packages <https://pkg.go.dev/golang.org/x/crypto/ripemd160>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class WeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            full_descr=__doc__,
            cwe_id=328,
            message="Use of weak hash function '{}' does not meet security "
            "expectations.",
            targets=("call"),
            wildcards={},
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "golang.org/x/crypto/md4.New",
            "golang.org/x/crypto/ripemd160.New",
        ]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="Use a more secure hashing algorithm like sha256.",
                inserted_content="sha256.New",
            )
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
                fixes=fixes,
            )
        elif call.name_qualified in [
            "golang.org/x/crypto/md4.Sum",
            "golang.org/x/crypto/ripemd160.Sum",
        ]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="Use a more secure hashing algorithm like sha256.",
                inserted_content="sha256.Sum",
            )
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
                fixes=fixes,
            )
