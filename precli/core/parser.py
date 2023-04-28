# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from importlib.metadata import entry_points

import tree_sitter_languages
from tree_sitter import Node

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

    def parse(self, file_name: str, data: bytes) -> list[Result]:
        self.results = []
        self.context = {"file_name": file_name}
        tree = self.parser.parse(data)
        self.visit([tree.root_node])
        return self.results

    def visit(self, nodes: list[Node]):
        for node in nodes:
            self.context["node"] = node
            visitor_fn = getattr(self, f"visit_{node.type}", self.visit)
            visitor_fn(node.children)

    def exec_rule(self, target: str) -> list[Result]:
        for rule in self.rules.values():
            if target in rule.targets:
                result = rule.analyze(self.context)
                if result:
                    self.results.append(result)
