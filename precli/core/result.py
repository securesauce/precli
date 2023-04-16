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

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def location(self) -> Location:
        return self._location

    @property
    def level(self) -> Level:
        return self._level

    @property
    def message(self) -> str:
        return self._message

    @property
    def rank(self):
        return self._rank

    def fixes(self) -> list[Fix]:
        pass
