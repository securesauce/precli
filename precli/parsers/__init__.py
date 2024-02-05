# Copyright 2024 Secure Saurce LLC
from abc import ABC
from importlib.metadata import entry_points

import tree_sitter_languages
from tree_sitter import Node

from precli.core.artifact import Artifact
from precli.core.location import Location
from precli.core.result import Result
from precli.core.suppression import Suppression
from precli.rules import Rule


class Parser(ABC):
    """
    Base class of a language specific parser.

    The parser handles most of the main functions including parsing nodes,
    processing rules based on those nodes, and compiling a list of results.

    Each parser is designed to operate on a specific programming language.
    """

    def __init__(self, lang: str, enabled: list = None, disabled: list = None):
        """
        Initialize a new parser.

        :param str lang: programming language name
        :param list enabled: list of rules to enable
        :param list disabled: list of rules to disable
        """
        self._lexer = lang
        self.tree_sitter_language = tree_sitter_languages.get_language(lang)
        self.tree_sitter_parser = tree_sitter_languages.get_parser(lang)
        self.rules = {}
        self.wildcards = {}

        discovered_rules = entry_points(group=f"precli.rules.{lang}")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()(rule.name)

            if enabled is not None and (
                enabled == ["all"]
                or self.rules[rule.name].id in enabled
                or self.rules[rule.name].name in enabled
            ):
                self.rules[rule.name].default_config.enabled = True

            if disabled is not None and (
                disabled == ["all"]
                or self.rules[rule.name].id in disabled
                or self.rules[rule.name].name in disabled
            ):
                self.rules[rule.name].default_config.enabled = False

            if self.rules[rule.name].wildcards:
                self.wildcards |= self.rules[rule.name].wildcards

    @property
    def lexer(self) -> str:
        """
        The name of the lexer

        :return: lexer name
        :rtype: str
        """
        return self._lexer

    def parse(self, artifact: Artifact) -> list[Result]:
        """
        File extension of files this parser can handle.

        :param Artifact artifact: artifact representing the file

        :return: list of results
        :rtype: list
        """
        self.results = []
        self.context = {"artifact": artifact}
        if artifact.contents is None:
            with open(artifact.file_name, "rb") as fdata:
                artifact.contents = fdata.read()
        tree = self.tree_sitter_parser.parse(artifact.contents)
        self.visit([tree.root_node])

        for result in self.results:
            suppression = self.suppressions.get(result.location.start_line)
            if suppression and result.rule_id in suppression.rules:
                result.suppression = suppression

        return self.results

    def visit(self, nodes: list[Node]):
        """
        Generic visitor of nodes.

        THis function will visit each node and attempt to call a more
        specific visit function if defined based on the node type.

        :param list nodes: list of nodes
        """
        for node in nodes:
            # print(node)

            self.context["node"] = node
            visitor_fn = getattr(self, f"visit_{node.type}", self.visit)
            visitor_fn(node.children)

    def visit_comment(self, nodes: list[Node]):
        comment = self.context["node"].text.decode()

        suppressed = self.SUPPRESS_COMMENT.search(comment)
        if suppressed is None:
            return

        matches = suppressed.groupdict()
        suppressed_rules = matches.get("rules")

        if suppressed_rules is None:
            return

        rules = set()
        for rule in self.SUPPRESSED_RULES.finditer(suppressed_rules):
            rule_name_or_id = rule.group(1)
            if Rule.get_by_id(rule_name_or_id) is not None:
                rules.add(rule_name_or_id)

        if not rules:
            return

        suppression = Suppression(
            location=Location(node=self.context["node"]),
            rules=rules,
        )

        prev_node = self.context["node"].prev_sibling
        node = self.context["node"]

        if prev_node.end_point[0] == node.start_point[0]:
            self.suppressions[node.start_point[0] + 1] = suppression
        else:
            self.suppressions[node.start_point[0] + 2] = suppression

        # TODO: add the justification to the suppression

    def visit_ERROR(self, nodes: list[Node]):
        err_node = self.first_match(self.context["node"], "ERROR")
        if err_node is None:
            err_node = self.context["node"]

        raise SyntaxError(
            "Syntax error while parsing file.",
            (
                self.context["artifact"].file_name,
                err_node.start_point[0] + 1,
                err_node.start_point[1] + 1,
                err_node.text.decode(errors="ignore"),
                err_node.end_point[0] + 1,
                err_node.end_point[1] + 1,
            ),
        )

    def first_match(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.named_children))
        return child[0] if child else None

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
            if rule.default_config.enabled and target in rule.targets:
                context = self.context
                context["symtab"] = self.current_symtab
                result = rule.analyze(self.context, **kwargs)
                if result is not None:
                    self.results.append(result)
