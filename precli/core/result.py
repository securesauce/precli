# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
from precli.core.level import Level
from precli.core.location import Location
from precli.core.rule import Rule


class Result:
    def __init__(
        self,
        rule_id: str,
        file_name: str,
        start_point: tuple,
        end_point: tuple,
        level: Level = None,
        message: str = None,
    ):
        self._rule_id = rule_id
        self._location = Location(
            file_name=file_name,
            start_line=start_point[0],
            end_line=end_point[0],
            start_column=start_point[1],
            end_column=end_point[1],
        )
        self._level = level
        self._message = message

    @property
    def rule_id(self) -> str:
        return self._rule_id

    @property
    def location(self) -> Location:
        return self._location

    @property
    def level(self) -> Level:
        if not self._level:
            default_config = Rule.get_by_id(self._rule_id).default_config
            return default_config.level
        return self._level

    @property
    def message(self) -> str:
        if not self._message:
            return Rule.get_by_id(self._rule_id).message
        return self._message

    @property
    def rank(self):
        default_config = Rule.get_by_id(self._rule_id).default_config
        return default_config.rank

    def fixes(self) -> list[Fix]:
        pass
