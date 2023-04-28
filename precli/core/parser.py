# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from importlib.metadata import entry_points

import tree_sitter_languages

from precli.core.result import Result


class Parser(ABC):
    def __init__(self, lang: str):
        self.language = tree_sitter_languages.get_language(lang)
        self.parser = tree_sitter_languages.get_parser(lang)
        self.rules = {}

        discovered_rules = entry_points(group=f"precli.rules.{lang}")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()(rule.name)

    @abstractmethod
    def file_extension(self) -> str:
        pass

    @abstractmethod
    def parse(self, file_name: str, data: bytes) -> list[Result]:
        pass
