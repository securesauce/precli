# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
from precli.core.kind import Kind
from precli.core.level import Level
from precli.core.location import Location
from precli.core.suppression import Suppression
from precli.rules import Rule


class Result:
    def __init__(
        self,
        rule_id: str,
        kind: Kind = Kind.FAIL,
        level: Level = None,
        location: Location = None,
        message: str = None,
        fixes: list[Fix] = None,
        suppressions: list[Suppression] = None,
    ):
        self._rule_id = rule_id
        self._kind = kind
        default_config = Rule.get_by_id(self._rule_id).default_config
        self._rank = default_config.rank
        if level:
            self._level = level
        else:
            self._level = default_config.level
        self._location = location
        if message:
            self._message = message
        else:
            self._message = Rule.get_by_id(self._rule_id).message
        self._fixes = fixes if fixes is not None else []
        self._suppressions = suppressions if suppressions is not None else []

    @property
    def rule_id(self) -> str:
        """
        The ID of the rule.

        The IDs match PREXXXX where XXXX is a unique number.

        :return: rule ID
        :rtype: str
        """
        return self._rule_id

    @property
    def location(self) -> Location:
        """
        The location of the issue.

        A location object indicates coordinates within a source file where
        the issue was found.

        :return: location
        :rtype: Location
        """
        return self._location

    @property
    def kind(self) -> Kind:
        """
        The nature of the result.

        Typically having a value of pass or fail to indicate the nature of
        the result.

        :return: kind or nature of result
        :rtype: Kind
        """
        return self._kind

    @property
    def level(self) -> Level:
        """
        The result severity level.

        :return: severity level
        :rtype: Level
        """
        return self._level

    @property
    def message(self) -> str:
        """
        The result issue message.

        :return: issue message
        :rtype: str
        """
        return self._message

    @property
    def rank(self) -> float:
        """
        The rank of the issue.

        The value defaults to the value from the default configuration of the
        rule.

        :return: rank
        :rtype: float
        """
        return self._rank

    @property
    def fixes(self) -> list[Fix]:
        """
        The suggested fixes for the issue.

        :return: list of fixes
        :rtype: list
        """
        return self._fixes

    @property
    def suppressions(self) -> list[Suppression]:
        """
        Possible suppressions of the result.

        :return: list of suppressions
        :rtype: list
        """
        return self._suppressions
