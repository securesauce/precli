# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from importlib.metadata import entry_points

import tree_sitter_languages
from tree_sitter import Node
from tree_sitter import Tree

from precli.core.result import Result


class Parser(ABC):
    def __init__(self, lang: str):
        self.language = tree_sitter_languages.get_language(lang)
        self.parser = tree_sitter_languages.get_parser(lang)
        self.rules = {}

        discovered_rules = entry_points(group=f"precli.rules.{lang}")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()()

    @abstractmethod
    def file_extension(self) -> str:
        pass

    @staticmethod
    def traverse_tree(tree: Tree) -> Node:
        cursor = tree.walk()

        reached_root = False
        while reached_root is False:
            yield cursor.node

            if cursor.goto_first_child():
                continue

            if cursor.goto_next_sibling():
                continue

            retracing = True
            while retracing:
                if not cursor.goto_parent():
                    retracing = False
                    reached_root = True

                if cursor.goto_next_sibling():
                    retracing = False

    @abstractmethod
    def parse(self, file_name: str, data: bytes) -> list[Result]:
        pass
