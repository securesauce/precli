# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import ast
import re
from typing import Optional

from tree_sitter import Node

from precli.core.call import Call
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers.node_types import NodeTypes


class Go(Parser):
    def __init__(self):
        super().__init__("go")
        self.SUPPRESS_COMMENT = re.compile(r"suppress:? (?P<rules>[^#]+)?#?")
        self.SUPPRESSED_RULES = re.compile(r"(?:(GO\d\d\d|[a-z_]+),?)+")

    def file_extensions(self) -> list[str]:
        return [".go"]

    def rule_prefix(self) -> str:
        return "GO"

    def get_file_encoding(self, file_contents: str) -> str:
        return "utf-8"

    def is_test_code(self) -> bool:
        """
        Determine if analyzing test code.

        This function determines if the current position of the analysis
        is within unit test code. The purpose of which is to potentially
        ignore rules in test code.
        """
        return False

    def visit_source_file(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<source_file>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_declaration(self, nodes: list[Node]):
        if nodes[0].type == NodeTypes.IMPORT:
            if nodes[1].type == NodeTypes.IMPORT_SPEC:
                imps = self.import_spec(nodes[1].children)
                for key, value in imps.items():
                    self.current_symtab.put(key, NodeTypes.IMPORT, value)

            elif nodes[1].type == NodeTypes.IMPORT_SPEC_LIST:
                for child in nodes[1].named_children:
                    if child.type == NodeTypes.IMPORT_SPEC:
                        imps = self.import_spec(child.children)
                        for key, value in imps.items():
                            self.current_symtab.put(
                                key, NodeTypes.IMPORT, value
                            )

    def import_spec(self, nodes: list[Node]):
        imports = {}

        if nodes[0].type == NodeTypes.INTERPRETED_STRING_LITERAL:
            # import "fmt"
            package = ast.literal_eval(nodes[0].string)
            default_package = package.split("/")[-1]
            imports[default_package] = package

        elif nodes[0].type == NodeTypes.PACKAGE_IDENTIFIER:
            # import fm "fmt"
            # Can use fm.Println instead of fmt.Println
            if nodes[1].type == NodeTypes.INTERPRETED_STRING_LITERAL:
                alias = nodes[0].string
                package = ast.literal_eval(nodes[1].string)
                imports[alias] = package

        elif nodes[0].type == NodeTypes.DOT:
            # import . "fmt"
            # Can just call Println instead of fmt.Println
            # TODO: similar to Python wildcard imports
            pass

        elif nodes[0].type == NodeTypes.BLANK_IDENTIFIER:
            # import _ "some/driver"
            # The driver package is imported, and its init function is
            # executed, but no access any of its other functions or
            # variables directly.
            pass

        return imports

    def visit_function_declaration(self, nodes: list[Node]):
        func_id = self.context["node"].child_by_type(NodeTypes.IDENTIFIER)
        func = func_id.string
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def _get_var_node(self, node: Node) -> Optional[Node]:
        if (
            len(node.named_children) >= 2
            and node.named_children[0].type
            in (NodeTypes.IDENTIFIER, NodeTypes.ATTRIBUTE)
            and node.named_children[1].type == NodeTypes.IDENTIFIER
        ):
            return node.named_children[0]
        elif node.type == NodeTypes.ATTRIBUTE:
            return self._get_var_node(node.named_children[0])

    def _get_func_ident(self, node: Node) -> Optional[Node]:
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == NodeTypes.ATTRIBUTE:
            return self._get_func_ident(node.named_children[1])
        if node.type == NodeTypes.IDENTIFIER:
            return node

    def visit_call_expression(self, nodes: list[Node]):
        func_call_qual = self.resolve(nodes[0])
        func_call_args = self.get_func_args(nodes[1])

        if self.context["node"].children:
            # (selector_expression | identifier) argument_list
            func_node = self.context["node"].children[0]
            var_node = self._get_var_node(func_node)
            ident_node = self._get_func_ident(func_node)
            arg_list_node = self.context["node"].children[1]

            call = Call(
                node=self.context["node"],
                name=func_call_qual,
                name_qual=func_call_qual,
                func_node=func_node,
                var_node=var_node,
                ident_node=ident_node,
                arg_list_node=arg_list_node,
                args=func_call_args,
            )

            self.analyze_node(NodeTypes.CALL_EXPRESSION, call=call)

            if call.var_node is not None:
                symbol = self.current_symtab.get(call.var_node.string)
                if symbol is not None and symbol.type == NodeTypes.IDENTIFIER:
                    symbol.push_call(call)
            else:
                # TODO: why is var_node None?
                pass

        self.visit(nodes)

    def get_func_args(self, node: Node) -> list:
        if node.type != NodeTypes.ARGUMENT_LIST:
            return []

        args = []
        for child in node.named_children:
            args.append(self.resolve(child, default=child))

        return args

    def get_qual_name(self, node: Node) -> Optional[Symbol]:
        nodetext = node.string
        symbol = self.current_symtab.get(nodetext)

        if symbol is not None:
            return symbol
        for child in node.children:
            return self.get_qual_name(child)

    def unchain(self, node: Node, result: list):
        """
        Unchain an attribute into its component identifiers skipping
        over argument_list of a call node and such.
        """
        if node.type == NodeTypes.IDENTIFIER:
            result.append(node.string)
        for child in node.named_children:
            if child.type != NodeTypes.ARGUMENT_LIST:
                self.unchain(child, result)

    def resolve(self, node: Node, default=None):
        """
        Resolve the given node into its liternal value.
        """
        nodetext = node.string
        if isinstance(default, Node):
            default = default.string

        try:
            if node.type == NodeTypes.SELECTOR_EXPRESSION:
                nodetext = node.string
                symbol = self.get_qual_name(node)
                if symbol is not None:
                    value = self.join_symbol(nodetext, symbol)
            elif node.type == NodeTypes.IDENTIFIER:
                symbol = self.get_qual_name(node)
                if symbol is not None:
                    value = self.join_symbol(nodetext, symbol)
            elif node.type == NodeTypes.INTERPRETED_STRING_LITERAL:
                # TODO: don't use ast
                value = ast.literal_eval(nodetext)
            elif node.type == NodeTypes.INT_LITERAL:
                # TODO: hex, octal, binary
                try:
                    value = int(nodetext)
                except ValueError:
                    value = nodetext
            elif node.type == NodeTypes.FLOAT_LITERAL:
                try:
                    value = float(nodetext)
                except ValueError:
                    value = nodetext
            elif node.type == NodeTypes.TRUE:
                value = True
            elif node.type == NodeTypes.FALSE:
                value = False
            elif node.type == NodeTypes.NIL:
                value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
