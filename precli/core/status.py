# Copyright 2023 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import enum


class Status(str, enum.Enum):
    """
    The status of a suppression.

    :var ACCEPTED: The suppression is accepted.
    :vartype ACCEPTED: str

    :var UNDER_REVIEW: Under review on whether to suppress it.
    :vartype UNDER_REVIEW: str

    :var REJECTED: It was decided not to supporess the result.
    :vartype REJECTED: str

    """

    ACCEPTED = "accepted"
    UNDER_REVIEW = "underReview"
    REJECTED = "rejected"
