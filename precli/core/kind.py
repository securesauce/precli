# Copyright 2023 Secure Sauce LLC
import enum


class Kind(str, enum.Enum):
    """
    The nature of the result.

    :var FAIL: A problem was found.
    :vartype FAIL: str

    :var REVIEW: Requires review to decide if it represents a problem.
    :vartype REVIEW: str

    :var NOT_APPLICABLE: Was not evaluated because it does not apply.
    :vartype NOT_APPLICABLE: str

    :var INFORMATIONAL: Info that does not indicate the presence of a problem.
    :vartype INFORMATIONAL: str

    :var OPEN: Insufficient information to decide whether a problem exists.
    :vartype OPEN: str

    :var PASS: No problem was found.
    :vartype PASS: str
    """

    FAIL = "fail"
    REVIEW = "review"
    NOT_APPLICABLE = "notApplicable"
    INFORMATIONAL = "informational"
    OPEN = "open"
    PASS = "pass"
