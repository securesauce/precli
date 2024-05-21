# Copyright 2024 Secure Sauce LLC
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
        """Whether the configuration indicates the rule is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Set whether the rule is enabled"""
        self._enabled = enabled

    @property
    def level(self) -> Level:
        """The default severity level."""
        return self._level

    @property
    def rank(self) -> float:
        """The default rank for the rule."""
        return self._rank
