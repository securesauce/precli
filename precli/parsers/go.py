# Copyright 2024 Secure Saurce LLC
import ast
import re

from tree_sitter import Node

from precli.core.call import Call
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers import tokens


class Go(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("go", enabled, disabled)
        self.SUPPRESS_COMMENT = re.compile(
            r"// suppress:? (?P<rules>[^#]+)?#?"
        )
        self.SUPPRESSED_RULES = re.compile(r"(?:(GO\d\d\d|[a-z_]+),?)+")

    def file_extensions(self) -> list[str]:
        return [".go"]

    def visit_source_file(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<source_file>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_declaration(self, nodes: list[Node]):
        if nodes[0].type == tokens.IMPORT:
            if nodes[1].type == tokens.IMPORT_SPEC:
                imps = self.import_spec(nodes[1].children)
                for key, value in imps.items():
                    self.current_symtab.put(key, tokens.IMPORT, value)

            elif nodes[1].type == tokens.IMPORT_SPEC_LIST:
                for child in nodes[1].named_children:
                    if child.type == tokens.IMPORT_SPEC:
                        imps = self.import_spec(child.children)
                        for key, value in imps.items():
                            self.current_symtab.put(key, tokens.IMPORT, value)

    def import_spec(self, nodes: list[Node]):
        imports = {}

        match nodes[0].type:
            case tokens.INTERPRETED_STRING_LITERAL:
                # import "fmt"
                package = ast.literal_eval(nodes[0].text.decode())
                default_package = package.split("/")[-1]
                imports[default_package] = package

            case tokens.PACKAGE_IDENTIFIER:
                # import fm "fmt"
                # Can use fm.Println instead of fmt.Println
                if nodes[1].type == tokens.INTERPRETED_STRING_LITERAL:
                    alias = nodes[0].text.decode()
                    package = ast.literal_eval(nodes[1].text.decode())
                    imports[alias] = package

            case tokens.DOT:
                # import . "fmt"
                # Can just call Println instead of fmt.Println
                # TODO: similar to Python wildcard imports
                pass

            case tokens.BLANK_IDENTIFIER:
                # import _ "some/driver"
                # The driver package is imported, and its init function is
                # executed, but no access any of its other functions or
                # variables directly.
                pass

        return imports

    def visit_function_declaration(self, nodes: list[Node]):
        func_id = self.child_by_type(self.context["node"], tokens.IDENTIFIER)
        func = func_id.text.decode()
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_call_expression(self, nodes: list[Node]):
        func_call_qual = self.resolve(nodes[0])
        func_call_args = self.get_func_args(nodes[1])

        call = Call(
            node=self.context["node"],
            name=func_call_qual,
            name_qual=func_call_qual,
            args=func_call_args,
        )

        self.analyze_node(self.context["node"].type, call=call)

        if call.var_node is not None:
            symbol = self.current_symtab.get(call.var_node.text.decode())
            if symbol is not None and symbol.type == tokens.IDENTIFIER:
                symbol.push_call(call)
        else:
            # TODO: why is var_node None?
            pass

        self.visit(nodes)

    def get_func_args(self, node: Node) -> list:
        if node.type != tokens.ARGUMENT_LIST:
            return []

        args = []
        for child in node.named_children:
            args.append(self.resolve(child, default=child))

        return args

    def get_qual_name(self, node: Node) -> Symbol:
        nodetext = node.text.decode()
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
        if node.type == tokens.IDENTIFIER:
            result.append(node.text.decode())
        for child in node.named_children:
            if child.type != tokens.ARGUMENT_LIST:
                self.unchain(child, result)

    def resolve(self, node: Node, default=None):
        """
        Resolve the given node into its liternal value.
        """
        nodetext = node.text.decode()
        if isinstance(default, Node):
            default = default.text.decode()

        try:
            match node.type:
                case tokens.SELECTOR_EXPRESSION:
                    nodetext = node.text.decode()
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case tokens.IDENTIFIER:
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case tokens.INTERPRETED_STRING_LITERAL:
                    value = ast.literal_eval(nodetext)
                case tokens.INT_LITERAL:
                    # TODO: hex, octal, binary
                    try:
                        value = int(nodetext)
                    except ValueError:
                        value = nodetext
                case tokens.FLOAT_LITERAL:
                    try:
                        value = float(nodetext)
                    except ValueError:
                        value = nodetext
                case tokens.TRUE:
                    value = True
                case tokens.FALSE:
                    value = False
                case tokens.NIL:
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
