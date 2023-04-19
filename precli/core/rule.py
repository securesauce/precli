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
        cwe: int,
        message: str,
        config: Config = None,
        help_url: str = None,
    ):
        self._id = id
        self._name = name
        self._full_descr = full_descr
        self._cwe = Rule._cwedb.get(cwe)
        self._message = message
        if not config:
            self._config = Config()
        if not help_url:
            # TDOO: generate URL based on rule
            self._help_url = ""
        Rule._rules[id] = self

    @property
    def id(self) -> str:
        return self._id

    @staticmethod
    def get_by_id(id: str) -> Self:
        return Rule._rules.get(id)

    @property
    def name(self) -> str:
        return self._name

    @property
    def short_descr(self) -> str:
        return self._cwe.description

    @property
    def full_descr(self) -> str:
        return self._full_descr

    @property
    def help_url(self) -> str:
        return self._help_url

    @property
    def default_config(self) -> Config:
        return self._config

    @property
    def cwe(self) -> Weakness:
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
    def match_call_pos_arg(
        context: dict,
        arg_pos: int = 0,
        arg_value: str = None,
    ) -> bool:
        if context["node"].type == "call":
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
        if context["node"].type == "call" and context["func_call_args"]:
            if arg_name in context["func_call_kwargs"]:
                # TODO: what if a tuple or list? arg_value assumes str
                return context["func_call_kwargs"][arg_name] == arg_value

    @abstractmethod
    def analyze(self, context: dict):
        """Analyze the code and return a result.

        :return: an issue as a Result object or None
        :rtype: Result
        """
