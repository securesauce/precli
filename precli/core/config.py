# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level


class Config:
    def __init__(
        self,
        enabled: bool = True,
        level: Level = Level.WARNING,
        rank: float = -1.0,
    ):
        self._enabled = enabled
        self._level = level
        self._rank = rank

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def level(self) -> Level:
        return self._level

    @property
    def rank(self) -> float:
        return self._rank
