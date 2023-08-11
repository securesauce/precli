# Copyright 2023 Secure Saurce LLC
from precli.core.location import Location
from precli.core.status import Status


class Suppression:
    def __init__(
        self,
        location: Location,
        rules: set[str],
        kind: str = "inSource",
        status: Status = Status.ACCEPTED,
        justification: str = None,
    ):
        self._location = location
        self._rules = rules
        self._kind = kind
        self._status = status
        self._justification = justification

    @property
    def location(self) -> Location:
        """
        Specifies the location of the suppression.

        :return: location of suppression
        :rtype: Location
        """
        return self._location

    @property
    def rules(self) -> set[str]:
        """
        What rules are being suppressed.

        :return: set of rule ID/names
        :rtype: set
        """
        return self._rules

    @property
    def kind(self) -> str:
        """
        The kind of suppression. This can be one of two values:
            "inSource" supporessed inline in the code
            "external" suppressed in an external persistent store

        :return: kind of suppression
        :rtype: str
        """
        return self._kind

    @property
    def status(self) -> Status:
        """
        The status of the suppression.

        :return: status on whether to suppress
        :rtype: Status
        """
        return self._status

    @property
    def justification(self) -> str:
        """
        User-supplied string that explains why the result was suppressed.

        :return: why the result was suppressed
        :rtype: str
        """
        return self._justification
