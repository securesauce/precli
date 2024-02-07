# Copyright 2024 Secure Saurce LLC
r"""
=========================================
Reversible One Way Hash in Crypto Package
=========================================

The Go ``crypto`` package provides a number of functions for hashing data.
However, some of the hash algorithms supported by hashlib are insecure and
should not be used. These insecure hash algorithms include ``MD5`` and
``SHA-1``.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and passwords hashed
with MD5 can be easily cracked by attackers.

The SHA-1 hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and
passwords hashed with SHA-1 can be easily cracked by attackers.

-------
Example
-------

.. code-block:: go
   :linenos:
   :emphasize-lines: 4,9

    package main

    import (
        "crypto/md5"
        "fmt"
    )

    func main() {
        h := md5.New()
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

 - `md5 package - crypto_md5 - Go Packages <https://pkg.go.dev/crypto/md5>`_
 - `sha1 package - crypto_sha1 - Go Packages <https://pkg.go.dev/crypto/sha1>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_

.. versionadded:: 0.2.1

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
            "crypto/md5.New",
            "crypto/sha1.New",
        ]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="Use a more secure hashing algorithm like sha256.",
                inserted_content="sha256.New",
            )
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
                fixes=fixes,
            )
        elif call.name_qualified in [
            "crypto/md5.Sum",
            "crypto/sha1.Sum",
        ]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="Use a more secure hashing algorithm like sha256.",
                inserted_content="sha256.Sum",
            )
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                level=Level.ERROR,
                message=self.message.format(call.name_qualified),
                fixes=fixes,
            )
