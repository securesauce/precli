# Copyright 2024 Secure Saurce LLC
r"""
============================================
Observable Timing Discrepancy in Hmac Module
============================================

Do not use Python's == operator to compare HMAC digests. The == operator is
not designed to be used for cryptographic comparisons, and it can be
vulnerable to timing attacks. Instead, use the hmac.compare_digest() function
to compare HMAC digests.

The == operator works by comparing the length and contents of two objects.
However, this can be a problem for HMAC digests, because the length of an
HMAC digest is not necessarily unique. For example, two different messages
with the same key will have the same HMAC digest.

A timing attack is a type of attack that exploits the time it takes to
execute a piece of code. In the case of HMAC digests, a timing attack could
be used to determine whether two messages have the same HMAC digest. This
could be used to break the security of an HMAC-protected system.

The hmac.compare_digest() function is designed to be used for cryptographic
comparisons. It works by comparing the binary representations of two HMAC
digests. This makes it more resistant to timing attacks.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 13

    import hmac


    received_digest = (
        b"\xe2\x93\x08\x19T8\xdc\x80\xef\x87\x90m\x1f\x9d\xf7\xf2"
        "\xf5\x10>\xdbf\xa2\xaf\xf7x\xcdX\xdf"
    )

    key = b"my-secret-key"
    password = b"pass"
    digest = hmac.digest(key, password, digest="sha224")

    return digest == received_digest

-----------
Remediation
-----------

The recommendation is to replace the == operator with the function
``compare_digest``.

.. code-block:: python
   :linenos:
   :emphasize-lines: 13

    import hmac


    received_digest = (
        b"\xe2\x93\x08\x19T8\xdc\x80\xef\x87\x90m\x1f\x9d\xf7\xf2"
        "\xf5\x10>\xdbf\xa2\xaf\xf7x\xcdX\xdf"
    )

    key = b"my-secret-key"
    password = b"pass"
    digest = hmac.digest(key, password, digest="sha224")

    return hmac.compare_digest(digest, received_digest)

.. seealso::

 - `hmac — Keyed-Hashing for Message Authentication <https://docs.python.org/3/library/hmac.html>`_
 - `CWE-208: Observable Timing Discrepancy <https://cwe.mitre.org/data/definitions/208.html>`_

.. versionadded:: 0.1.4

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


TIMING_VULNERABLE = (
    "hmac.digest",
    "hmac.new.digest",
    "hmac.new.hexdigest",
    "hmac.HMAC.digest",
    "hmac.HMAC.hexdigest",
)


class HmacTimingAttack(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="observable_timing_discrepancy",
            full_descr=__doc__,
            cwe_id=208,
            message="Comparing digests with the '==' operator is vulnerable "
            "to timing attacks.",
            targets=("comparison_operator"),
            wildcards={
                "hmac.*": [
                    "new",
                    "digest",
                    "HMAC",
                    "HMAC.digest",
                    "HMAC.hexdigest",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        comparison = kwargs.get("comparison")

        if comparison.operator == "==" and (
            comparison.left_hand in TIMING_VULNERABLE
            or comparison.right_hand in TIMING_VULNERABLE
        ):
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=comparison.node),
                description="Use the 'hmac.compare_digest' function instead "
                "of the '==' operator to reduce the vulnerability to timing "
                "attacks.",
                inserted_content=f"hmac.compare_digest("
                f"{comparison.left_node.text.decode()}, "
                f"{comparison.right_node.text.decode()})",
            )

            return Result(
                rule_id=self.id,
                artifact=context["artifact"],
                location=Location(node=comparison.operator_node),
                level=Level.ERROR,
                fixes=fixes,
            )
