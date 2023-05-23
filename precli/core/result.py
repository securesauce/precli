# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
from precli.core.level import Level
from precli.core.location import Location
from precli.core.rule import Rule


class Result:
    def __init__(
        self,
        rule_id: str,
        location: Location,
        level: Level = None,
        message: str = None,
        fixes: list[Fix] = None,
    ):
        self._rule_id = rule_id
        self._location = location
        default_config = Rule.get_by_id(self._rule_id).default_config
        self._rank = default_config.rank
        if level:
            self._level = level
        else:
            self._level = default_config.level
        if message:
            self._message = message
        else:
            self._message = Rule.get_by_id(self._rule_id).message
        self._fixes = fixes if fixes is not None else []

    @property
    def rule_id(self) -> str:
        """
        The ID of the rule.

        The IDs match a of PREXXX where XXX is a unique number. 001-299
        correspond to stdlib rules, whereas 300-999 corresponds to third-party
        rules.

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
