# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from typing import Self

from cwe import Database
from cwe import Weakness
from tree_sitter import Node

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
    ) -> Node:
        """
        Match any call name to the given function names.

        :param dict context: current context of the parse
        :param list funcs: list of function names to match

        :return: the call node if match found or None
        :rtype: Node
        """
        if context["func_call_qual"] in funcs:
            return True

    @staticmethod
    def match_call_pos_arg(
        context: dict,
        arg_pos: int,
        arg_value: list[str],
    ) -> Node:
        """
        Match an argument at given position and value.

        :param dict context: current context of the parse
        :param int arg_pos: index of positional argument
        :param list arg_value: value of positional argument

        :return: the argument node if match found or None
        :rtype: Node
        """
        func_call_args = context["func_call_args"]
        if func_call_args and len(func_call_args) > arg_pos:
            arg = func_call_args[arg_pos]
            # TODO: what if a tuple or list? arg_value assumes str
            if not isinstance(arg, dict) and arg in arg_value:
                return Rule.get_positional_arg(context["node"], arg_pos)

    @staticmethod
    def get_positional_arg(parent: Node, position: int) -> Node:
        if parent.type != "call":
            # If parent is the attribute/identifier and not a "call" node
            # use parent instead
            parent = parent.parent
        if (
            len(parent.children) > 1
            and parent.children[1].type == "argument_list"
        ):
            argument_list = parent.children[1]
            for i, child in enumerate(argument_list.named_children):
                if i == position:
                    return child

    @staticmethod
    def match_call_kwarg(
        context: dict,
        arg_name: str,
        arg_value: list[str],
    ) -> Node:
        """
        Match an argument within the keyword arguments.

        :param dict context: current context of the parse
        :param str arg_name: name of keyword argument
        :param list arg_value: value of keyword argument

        :return: the argument node if match found or None
        :rtype: Node
        """
        if (
            context["func_call_kwargs"]
            and arg_name in context["func_call_kwargs"]
        ):
            # TODO: what if a tuple or list? arg_value assumes str
            if context["func_call_kwargs"][arg_name] in arg_value:
                return Rule.get_keyword_arg(context["node"], arg_name)

    @staticmethod
    def get_keyword_arg(parent: Node, arg_name: str) -> Node:
        if parent.type != "call":
            # If parent is the attribute/identifier and not a "call" node
            # use parent instead
            parent = parent.parent
        if (
            len(parent.children) > 1
            and parent.children[1].type == "argument_list"
        ):
            argument_list = parent.children[1]
            for child in argument_list.named_children:
                if child.type == "keyword_argument":
                    keyword = child.named_children[0].text.decode()
                    if keyword == arg_name:
                        return child.named_children[1]

    @staticmethod
    def get_func_ident(node: Node):
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == "attribute":
            return Rule.get_func_ident(node.named_children[1])
        if node.type == "identifier":
            return node

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
    def analyze(self, context: dict, *args: list, **kwargs: dict):
        """Analyze the code and return a result.

        :param dict context: current context of the parse
        :param list args: arguments
        :param dict kwargs: keyword arguments

        :return: an issue as a Result object or None
        :rtype: Result
        """
