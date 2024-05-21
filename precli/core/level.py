# Copyright 2023 Secure Sauce LLC
import enum


class Level(str, enum.Enum):
    """
    The severity level of a result.

    :var ERROR: A serious problem was found.
    :vartype FAILURE: str

    :var WARNING: A problem was found.
    :vartype WARNING: str

    :var NOTE: A minor problem was found.
    :vartype NOTE: str

    :var NONE: No problem found
    :vartype NONE: str
    """

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"
    NONE = "none"

    def to_severity(self) -> str:
        """
        Returns a security severity value.

        Code scanning translates numerical scores as follows:
        over 9.0 is critical, 7.0 to 8.9 is high, 4.0 to 6.9 is medium and
        3.9 or less is low.

        :return: severity as float
        :rtype: float
        """
        if self.value == self.ERROR:
            return "8.0"
        elif self.value == self.WARNING:
            return "5.0"
        elif self.value == self.NOTE:
            return "3.0"
        else:
            return "0.0"
