# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
from precli.core.level import Level
from precli.core.location import Location


class Result:

    def __init__(self, id, level, message):
        self._id = id
        self._level = level
        self._message = message

    def rule_id(self) -> str:
        return self._id

    def level(self) -> Level:
        return self._level

    def message(self) -> str:
        return self._message

    def locations(self) -> list[Location]:
        pass

    def rank(self):
        pass

    def fixes(self) -> list[Fix]:
        pass
