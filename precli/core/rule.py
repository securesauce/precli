# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from typing import Self

from cwe import Database
from cwe import Weakness

from precli.core.config import Config


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
        if not config:
            self._config = Config()
        if not help_url:
            # TDOO: generate URL based on rule
            self._help_url = ""
        Rule._rules[id] = self

    @property
    def id(self) -> str:
        """
        The ID of the rule.

        The IDs match a of PREXXX where XXX is a unique number. 001-299
        correspond to stdlib rules, whereas 300-999 corresponds to third-party
        rules.

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
        return self._cwe.description

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
    def match_calls(
        context: dict,
        funcs: list[str],
    ) -> bool:
        """
        Match any call name to the given function names.

        :param dict context: current context of the parse
        :param list funcs: list of function names to match

        :return: true if match found
        :rtype: bool
        """
        if context["func_call_qual"] in funcs:
            return True

    @staticmethod
    def match_call_pos_arg(
        context: dict,
        arg_pos: int = 0,
        arg_value: str = None,
    ) -> bool:
        """
        Match an argument at given position and value.

        :param dict context: current context of the parse
        :param int arg_pos: index of positional argument
        :param str arg_value: value of positional argument

        :return: true if match found
        :rtype: bool
        """
        func_call_args = context["func_call_args"]
        if func_call_args and len(func_call_args) > arg_pos:
            arg = func_call_args[arg_pos]
            # TODO: what if a tuple or list? arg_value assumes str
            if not isinstance(arg, dict) and arg == arg_value:
                return True

    @staticmethod
    def match_call_kwarg(
        context: dict,
        arg_name: str,
        arg_value: str = None,
    ) -> bool:
        """
        Match an argument within the keyword arguments.

        :param dict context: current context of the parse
        :param str arg_name: name of keyword argument
        :param str arg_value: value of keyword argument

        :return: true if match found
        :rtype: bool
        """
        if context["func_call_args"]:
            if arg_name in context["func_call_kwargs"]:
                # TODO: what if a tuple or list? arg_value assumes str
                return context["func_call_kwargs"][arg_name] == arg_value

    @abstractmethod
    def analyze(self, context: dict):
        """Analyze the code and return a result.

        :param dict context: current context of the parse

        :return: an issue as a Result object or None
        :rtype: Result
        """
