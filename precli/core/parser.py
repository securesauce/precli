# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod
from importlib.metadata import entry_points

import tree_sitter_languages
from tree_sitter import Node

from precli.core.result import Result


class Parser(ABC):
    """
    Base class of a language specific parser.

    The parser handles most of the main functions including parsing nodes,
    processing rules based on those nodes, and compiling a list of results.

    Each parser is designed to operate on a specific programming language.
    """

    def __init__(self, lang: str):
        self.language = tree_sitter_languages.get_language(lang)
        self.parser = tree_sitter_languages.get_parser(lang)
        self.rules = {}
        self.wildcards = {}

        discovered_rules = entry_points(group=f"precli.rules.{lang}")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()(rule.name)
            if self.rules[rule.name].wildcards:
                self.wildcards |= self.rules[rule.name].wildcards

    @abstractmethod
    def file_extension(self) -> str:
        """
        File extension of files this parser can handle.

        :return: file extension glob such as "*.py"
        :rtype: str
        """

    def parse(self, file_name: str, data: bytes = None) -> list[Result]:
        """
        File extension of files this parser can handle.

        :param str file_name: name of file name to parse
        :param bytes data: file data

        :return: list of results
        :rtype: list
        """
        self.results = []
        self.context = {"file_name": file_name}
        if data is None:
            with open(file_name, "rb") as fdata:
                data = fdata.read()
        tree = self.parser.parse(data)
        self.visit([tree.root_node])
        return self.results

    def visit(self, nodes: list[Node]):
        """
        Generic visitor of nodes.

        THis function will visit each node and attempt to call a more
        specific visit function if defined based on the node type.

        :param list nodes: list of nodes
        """
        for node in nodes:
            self.context["node"] = node
            visitor_fn = getattr(self, f"visit_{node.type}", self.visit)
            visitor_fn(node.children)

    def process_rules(self, target: str, **kwargs: dict) -> list[Result]:
        """
        Process the rules based on target.

        This function will iterate through all rules that are designed to
        handle the given node type (target).

        :param str target: process nodes of this node type

        :return: list of results
        :rtype: list
        """
        for rule in self.rules.values():
            if target in rule.targets:
                result = rule.analyze(self.context, **kwargs)
                if result:
                    self.results.append(result)
