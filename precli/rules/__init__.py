# Copyright 2024 Secure Sauce LLC
from abc import ABC
from typing import Self

from precli.core.config import Config
from precli.core.cwe import Cwe
from precli.core.fix import Fix
from precli.core.location import Location


class Rule(ABC):
    _rules = {}

    def __init__(
        self,
        id: str,
        name: str,
        description: str,
        cwe_id: int,
        message: str,
        wildcards: dict[str, list[str]] = None,
        config: Config = None,
        help_url: str = None,
    ):
        self._id = id
        self._name = name
        try:
            start = description.index("\n# ") + 3
        except ValueError:
            start = 0
        try:
            end = description.index("\n\n")
        except ValueError:
            end = len(description)
        self._short_descr = description[start:end].replace("`", "")
        try:
            start = description.index("\n\n") + 2
        except ValueError:
            start = 0
        self._full_descr = description[start:]
        self._cwe = Cwe(cwe_id)
        self._message = message
        self._wildcards = wildcards
        self._config = Config() if not config else config
        self._enabled = self._config.enabled
        self._help_url = f"https://docs.securesauce.dev/rules/{id}"
        Rule._rules[id] = self

    @property
    def id(self) -> str:
        """
        The ID of the rule.

        The IDs match PREXXXX where XXXX is a unique number.

        :return: rule ID
        :rtype: str
        """
        return self._id

    @staticmethod
    def get_by_id(id: str) -> Self:
        """Get the rule instance by the given ID."""
        return Rule._rules.get(id)

    @property
    def name(self) -> str:
        """
        Get the rule name.

        The rule name is an alpha string corresponding to the CWE name
        but in snake case format.
        """
        return self._name

    @property
    def short_description(self) -> str:
        """Short description of the rule."""
        return self._short_descr

    @property
    def full_description(self) -> str:
        """Full description of the rule in markdown format."""
        return self._full_descr

    @property
    def help_url(self) -> str:
        """URL to help documentation."""
        return self._help_url

    @property
    def default_config(self) -> Config:
        """Default configuration for this rule."""
        return self._config

    @property
    def enabled(self) -> bool:
        """Whether the rule is enabled."""
        return self._enabled

    @enabled.setter
    def enabled(self, enabled):
        """Set whether the rule is enabled"""
        self._enabled = enabled

    @property
    def cwe(self) -> Cwe:
        """CWE weakness object for this rule."""
        return self._cwe

    @property
    def message(self) -> str:
        """Concise description message of the found issue."""
        return self._message

    @property
    def wildcards(self) -> dict[str, list[str]]:
        """
        Mapping of wildcard imports to concrete modules.

        This is necessary when some code has a wildcard import such as:
            from hashlib import *

        The * must map to concrete module names in order to fully resolve
        for rule matching.
        """
        return self._wildcards

    @staticmethod
    def get_fixes(
        context: dict,
        deleted_location: Location,
        description: str,
        inserted_content: str,
    ) -> list[Fix]:
        return [
            Fix(
                description=description,
                deleted_location=deleted_location,
                inserted_content=inserted_content,
            )
        ]
        # TODO(ericwb): verify the new content will fully resolve, otherwise
        # only make suggested fix as part of the description.
