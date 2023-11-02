# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from typing import Self

from cwe import Database
from cwe import Weakness

from precli.core.config import Config
from precli.core.fix import Fix
from precli.core.location import Location


class Rule(ABC):
    _rules = {}
    _cwedb = Database()

    def __init__(
        self,
        id: str,
        name: str,
        full_descr: str,
        cwe_id: int,
        message: str,
        targets: set[str],
        wildcards: dict[str, list[str]] = None,
        config: Config = None,
        help_url: str = None,
    ):
        self._id = id
        self._name = name
        self._full_descr = full_descr
        self._cwe = Rule._cwedb.get(cwe_id)
        self._message = message
        self._targets = targets
        self._wildcards = wildcards
        self._config = Config() if not config else config
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
        """
        Get the rule instance by the given ID.

        :param str id: rule ID

        :return: rule instance
        :rtype: Rule
        """
        return Rule._rules.get(id)

    @property
    def name(self) -> str:
        """
        Get the rule name.

        The rule name is an alpha string corresponding to the CWE name
        but in snake case format.

        :return: rule name
        :rtype: str
        """
        return self._name

    @property
    def short_descr(self) -> str:
        """
        Short description of the rule.

        :return: rule short description
        :rtype: str
        """
        try:
            start = self._full_descr.rindex("===\n") + 4
        except ValueError:
            start = 0
        try:
            end = self._full_descr.index("\n---")
        except ValueError:
            end = len(self._full_descr)
        return self._full_descr[start:end]

    @property
    def full_descr(self) -> str:
        """
        Full description of the rule.

        :return: rule full description
        :rtype: str
        """
        return self._full_descr

    @property
    def help_url(self) -> str:
        """
        URL to help documentation.

        :return: rule help documentation URL
        :rtype: str
        """
        return self._help_url

    @property
    def default_config(self) -> Config:
        """
        Default configuration for this rule.

        :return: configuration
        :rtype: Config
        """
        return self._config

    @property
    def cwe(self) -> Weakness:
        """
        CWE weakness object for this rule.

        :return: CWE weakness object
        :rtype: Weakness
        """
        return self._cwe

    @property
    def message(self) -> str:
        """
        Concise description message of the found issue.

        :return: issue message
        :rtype: str
        """
        return self._message

    @property
    def targets(self) -> set[str]:
        """
        Target node types this rule operates on.

        This property defines what node types the rule can process. For
        example, if the rule is designed to find suspicous calls, the rule
        can define target set of ("call").

        :return: set of target node types
        :rtype: set
        """
        return self._targets

    @property
    def wildcards(self) -> dict[str, list[str]]:
        """
        Mapping of wildcard imports to concrete modules.

        This is necessary when some code has a wildcard import such as:
            from hashlib import *

        The * must map to concrete module names in order to fully resolve
        for rule matching.

        :return: mapping of wildcard imports
        :rtype: dict
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

    @abstractmethod
    def analyze(self, context: dict, **kwargs: dict):
        """Analyze the code and return a result.

        :param dict context: current context of the parse
        :param list args: arguments
        :param dict kwargs: keyword arguments

        :return: an issue as a Result object or None
        :rtype: Result
        """
