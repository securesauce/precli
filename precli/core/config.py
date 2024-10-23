# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
from precli.core.level import Level


class Config:
    def __init__(
        self,
        enabled: bool = True,
        level: Level = Level.WARNING,
        rank: float = -1.0,
        parameters: dict = None,
    ):
        self._enabled = enabled
        self._level = level
        self._rank = rank
        self._parameters = parameters

    @property
    def enabled(self) -> bool:
        """Whether the configuration indicates the rule is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, enabled: bool):
        """Set whether the rule is enabled"""
        self._enabled = enabled

    @property
    def level(self) -> Level:
        """The default severity level."""
        return self._level

    @level.setter
    def level(self, level: Level):
        """Set the default severity level."""
        self._level = level

    @property
    def rank(self) -> float:
        """The default rank for the rule."""
        return self._rank

    @property
    def parameters(self) -> dict:
        """A dictionary of default parameters."""
        return self._parameters

    @parameters.setter
    def parameters(self, parameters: dict):
        """Set the dictionary of default parameters."""
        self._parameters = parameters
