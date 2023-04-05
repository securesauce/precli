# Copyright 2023 Secure Saurce LLC
import enum


class Level(str, enum.Enum):
    """
    The severity level of a result.

    :var ERROR: A serious problem was found.
    :vartype FAILURE: str

    :var WARNING: A problem was found.
    :vartype WARNING: str

    :var NOTE: A minor problem was found.
    :vartype NOTICE: str

    :var NONE: Annotation level of "none."
    :vartype NOTICE: str
    """

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"
