# Copyright 2023 Secure Saurce LLC
r"""
======================================
Reversible One Way Hash in Hmac Module
======================================

The Python module hmac provides a number of functions for creating and
verifying message authentication codes (MACs). However, some of the hash
algorithms supported by hmac are insecure and should not be used. These
insecure hash algorithms include `MD4``, ``MD5``, ``RIPEMD-160`` and ``SHA-1``.

The MD4 hash algorithm is a cryptographic hash function that was designed
in the late 1980s. MD4 is no longer considered secure, and MACs created with
MD4 can be easily cracked by attackers.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and MACs created with MD5
can be easily cracked by attackers.

RIPEMD-160 is a cryptographic hash function that was designed in 1996. It is
considered to be a secure hash function, but it is not as secure as SHA-256,
SHA-384, or SHA-512. In 2017, a collision attack was found for RIPEMD-160.
This means that it is possible to find two different messages that have the
same RIPEMD-160 hash. While this does not mean that RIPEMD-160 is completely
insecure, it does mean that it is not as secure as it once was.

The SHA-1 hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and MACs
created with SHA-1 can be easily cracked by attackers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import hmac


    secret_key = "This is my secret key."
    hmac_obj = hmac.new(key, digestmod="md5")
    message = "This is my message.".encode()
    hmac_obj.update(message)
    mac = hmac_obj.digest()

-----------
Remediation
-----------

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, ``SHA256``, ``SHA-384``, or ``SHA512``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import hmac


    secret_key = "This is my secret key."
    hmac_obj = hmac.new(key, digestmod="sha256")
    message = "This is my message.".encode()
    hmac_obj.update(message)
    mac = hmac_obj.digest()

.. seealso::

 - `hmac — Keyed-Hashing for Message Authentication <https://docs.python.org/3/library/hmac.html>`_
 - `CWE-328: Use of Weak Hash <https://cwe.mitre.org/data/definitions/328.html>`_
 - `NIST Policy on Hash Functions <https://csrc.nist.gov/projects/hash-functions>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


WEAK_HASHES = ("md4", "md5", "ripemd160", "sha", "sha1")


class HmacWeakHash(Rule):
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
                "hmac.*": [
                    "new",
                    "digest",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["hmac.new"]):
            call_args = kwargs["func_call_args"]
            call_kwargs = kwargs["func_call_kwargs"]
            name = (
                call_args[2]
                if len(call_args) > 2
                else call_kwargs.get("digestmod", None)
            )

            # TODO(ericwb): can hashlib.md5 be passed as digestmod

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    level=Level.ERROR,
                    message=self.message.format(name),
                )
        elif Rule.match_calls(context, ["hmac.digest"]):
            call_args = kwargs["func_call_args"]
            call_kwargs = kwargs["func_call_kwargs"]
            name = (
                call_args[2]
                if len(call_args) > 2
                else call_kwargs.get("digest", None)
            )

            if isinstance(name, str) and name.lower() in WEAK_HASHES:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    level=Level.ERROR,
                    message=self.message.format(name),
                )
