# Copyright 2024 Secure Sauce LLC
import warnings
from abc import ABC
from abc import abstractmethod
from importlib.metadata import entry_points

import tree_sitter_languages
from tree_sitter import Node

from precli.core.artifact import Artifact
from precli.core.location import Location
from precli.core.result import Result
from precli.core.suppression import Suppression
from precli.core.symtab import Symbol
from precli.rules import Rule


class Parser(ABC):
    """
    Base class of a language specific parser.

    The parser handles most of the main functions including parsing nodes,
    processing rules based on those nodes, and compiling a list of results.

    Each parser is designed to operate on a specific programming language.
    """

    def __init__(self, lang: str):
        """Initialize a new parser."""
        self._lexer = lang

        # Suppress the following warning from tree-sitter
        # FutureWarning: Language(path, name) is deprecated. Use
        # Language(ptr, name) instead.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            self.tree_sitter_language = tree_sitter_languages.get_language(
                lang
            )
            self.tree_sitter_parser = tree_sitter_languages.get_parser(lang)
        self.rules = {}
        self.wildcards = {}

        discovered_rules = entry_points(group=f"precli.rules.{lang}")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()(rule.name)

            if self.rules[rule.name].wildcards:
                for k, v in self.rules[rule.name].wildcards.items():
                    if k in self.wildcards:
                        self.wildcards[k] += v
                    else:
                        self.wildcards[k] = v

        def child_by_type(self, type: str) -> Node:
            # Return first child with type as specified
            child = list(filter(lambda x: x.type == type, self.named_children))
            return child[0] if child else None

        setattr(Node, "child_by_type", child_by_type)

    @property
    def lexer(self) -> str:
        """The name of the lexer"""
        return self._lexer

    @abstractmethod
    def file_extensions(self) -> list[str]:
        """File extension of files this parser can handle."""

    @abstractmethod
    def rule_prefix(self) -> str:
        """The prefix for the rule ID"""

    def parse(
        self, artifact: Artifact, enabled: list = None, disabled: list = None
    ) -> list[Result]:
        """File extension of files this parser can handle."""
        for rule in self.rules.values():
            if enabled is not None and (
                enabled == ["all"]
                or rule.id in enabled
                or rule.name in enabled
            ):
                rule.enabled = True

            if disabled is not None and (
                disabled == ["all"]
                or rule.id in disabled
                or rule.name in disabled
            ):
                rule.enabled = False

        self.results = []
        self.context = {"artifact": artifact}
        artifact.encoding = self.get_file_encoding(artifact.file_name)
        if artifact.contents is None:
            with open(artifact.file_name, "rb") as fdata:
                artifact.contents = fdata.read()
        tree = self.tree_sitter_parser.parse(artifact.contents)

        @property
        def string(self) -> str:
            return self.text.decode(encoding=artifact.encoding)

        setattr(Node, "string", string)

        self.visit([tree.root_node])

        for result in self.results:
            result.artifact = artifact

            suppression = self.suppressions.get(result.location.start_line)
            if suppression and result.rule_id in suppression.rules:
                result.suppression = suppression

        return self.results

    def visit(self, nodes: list[Node]):
        """
        Generic visitor of nodes.

        THis function will visit each node and attempt to call a more
        specific visit function if defined based on the node type.
        """
        for node in nodes:
            # print(node)

            self.context["node"] = node
            visitor_fn = getattr(self, f"visit_{node.type}", self.visit)
            visitor_fn(node.children)

    def visit_comment(self, nodes: list[Node]):
        comment = self.context["node"].string

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
        err_node = self.child_by_type(self.context["node"], "ERROR")
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

    def child_by_type(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.named_children))
        return child[0] if child else None

    def join_symbol(self, nodetext: str, symbol: Symbol):
        if isinstance(symbol.value, str):
            value = nodetext.replace(symbol.name, symbol.value, 1)
        else:
            value = symbol.value
        return value

    def analyze_node(self, node_type: str, **kwargs: dict) -> list[Result]:
        """
        Process the rules based on node_type.

        This function will iterate through all rules that are designed to
        handle the given node type (node_type).
        """
        fn = f"analyze_{node_type}"
        for rule in self.rules.values():
            if hasattr(rule, fn) and rule.enabled:
                context = self.context
                context["symtab"] = self.current_symtab

                analyze_fn = getattr(rule, fn)
                result = analyze_fn(self.context, **kwargs)

                if result is not None:
                    self.results.append(result)
