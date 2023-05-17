# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
from precli.core.level import Level
from precli.core.location import Location
from precli.core.rule import Rule


class Result:
    def __init__(
        self,
        rule_id: str,
        context: dict,
        file_name: str = None,
        start_point: tuple = None,
        end_point: tuple = None,
        level: Level = None,
        message: str = None,
        fixes: list[Fix] = None,
    ):
        self._rule_id = rule_id
        if start_point:
            start_line = start_point[0] + 1
            start_column = start_point[1]
        else:
            start_line = context["node"].start_point[0] + 1
            start_column = context["node"].start_point[1]
        if end_point:
            end_line = end_point[0] + 1
            end_column = end_point[1]
        else:
            end_line = context["node"].end_point[0] + 1
            end_column = context["node"].end_point[1]
        self._location = Location(
            file_name=file_name if file_name else context["file_name"],
            start_line=start_line,
            end_line=end_line,
            start_column=start_column,
            end_column=end_column,
        )
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
        self._fixes = fixes

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
