# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from typing import Self

from precli.core.config import Configuration
from precli.core.result import Result


class Rule(ABC):
    _rules = dict()

    def __init__(
        self,
        id: str,
        name: str,
        short_descr: str,
        full_descr: str,
        help_url: str,
        configuration: Configuration,
        cwe: int,
        message: str,
    ):
        self._id = id
        self._name = name
        self._short_descr = short_descr
        self._full_descr = full_descr
        self._help_url = help_url
        self._configuration = configuration
        self._cwe = cwe
        self._message = message
        Rule._rules[id] = self

    @property
    def id(self) -> str:
        return self._id

    def get_by_id(id: str) -> Self:
        return Rule._rules[id]

    @property
    def name(self) -> str:
        return self._name

    @property
    def short_description(self) -> str:
        return self._short_descr

    @property
    def full_description(self) -> str:
        return self._full_descr

    @property
    def help_url(self) -> str:
        return self._help_url

    @property
    def default_configuration(self) -> Configuration:
        return self._configuration

    @property
    def cwe(self) -> int:
        return self._cwe

    @property
    def message(self) -> str:
        return self._message

    @staticmethod
    def match_calls(
        context: dict,
        funcs: list[str],
    ) -> bool:
        if context["node"].type == "call":
            if context["func_call_qual"] in funcs:
                return True

    @staticmethod
    def match_call_arg_pos(
        context: dict,
        arg_pos: int = 0,
        arg_value: str = None,
    ) -> bool:
        if context["node"].type == "call":
            func_call_args = context["func_call_args"]
            if func_call_args and len(func_call_args) > arg_pos:
                arg = func_call_args[arg_pos]
                if not isinstance(arg, dict) and arg == arg_value:
                    return True

    @staticmethod
    def match_call_kwarg(
        context: dict,
        arg_name: str,
        arg_value: str = None,
    ) -> bool:
        if context["node"].type == "call" and context["func_call_args"]:
            if arg_name in context["func_call_kwargs"]:
                return context["func_call_kwargs"][arg_name] == arg_value

    @abstractmethod
    def analyze(self, context: dict) -> Result:
        """Analyze the code and return a result.

        :return: an issue as a Result object or None
        :rtype: Result
        """
        pass
