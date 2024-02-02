# Copyright 2024 Secure Saurce LLC
import ast
import re

from tree_sitter import Node

from precli.core.call import Call
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser


class Go(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("go", enabled, disabled)
        self.SUPPRESS_COMMENT = re.compile(
            r"// suppress:? (?P<rules>[^#]+)?#?"
        )
        self.SUPPRESSED_RULES = re.compile(r"(?:(GO\d\d\d|[a-z_]+),?)+")

    def visit_source_file(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<source_file>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_declaration(self, nodes: list[Node]):
        if nodes[0].type == "import":
            if nodes[1].type == "import_spec":
                imps = self.import_spec(nodes[1].children)
                for key, value in imps.items():
                    self.current_symtab.put(key, "import", value)

            elif nodes[1].type == "import_spec_list":
                for child in nodes[1].named_children:
                    if child.type == "import_spec":
                        imps = self.import_spec(child.children)
                        for key, value in imps.items():
                            self.current_symtab.put(key, "import", value)

    def import_spec(self, nodes: list[Node]):
        imports = {}

        match nodes[0].type:
            case "interpreted_string_literal":
                # import "fmt"
                package = ast.literal_eval(nodes[0].text.decode())
                default_package = package.split("/")[-1]
                imports[default_package] = package

            case "package_identifier":
                # import fm "fmt"
                # Can use fm.Println instead of fmt.Println
                if nodes[1].type == "interpreted_string_literal":
                    alias = nodes[0].text.decode()
                    package = ast.literal_eval(nodes[1].text.decode())
                    imports[alias] = package

            case "dot":
                # import . "fmt"
                # Can just call Println instead of fmt.Println
                # TODO: similar to Python wildcard imports
                pass

            case "blank_identifier":
                # import _ "some/driver"
                # The driver package is imported, and its init function is
                # executed, but no access any of its other functions or
                # variables directly.
                pass

        return imports

    def visit_function_declaration(self, nodes: list[Node]):
        func_id = self.first_match(self.context["node"], "identifier")
        func = func_id.text.decode()
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_call_expression(self, nodes: list[Node]):
        func_call_qual = self.literal_value(nodes[0])
        func_call_args = self.get_func_args(nodes[1])

        call = Call(
            node=self.context["node"],
            name=func_call_qual,
            name_qual=func_call_qual,
            args=func_call_args,
        )

        self.process_rules("call", call=call)

        if call.var_node is not None:
            symbol = self.current_symtab.get(call.var_node.text.decode())
            if symbol is not None and symbol.type == "identifier":
                symbol.push_call(call)
        else:
            # TODO: why is var_node None?
            pass

        self.visit(nodes)

    def get_func_args(self, node: Node) -> list:
        if node.type != "argument_list":
            return []

        args = []
        for child in node.named_children:
            args.append(self.literal_value(child, default=child))

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
        if node.type == "identifier":
            result.append(node.text.decode())
        for child in node.named_children:
            if child.type != "argument_list":
                self.unchain(child, result)

    def literal_value(self, node: Node, default=None):
        nodetext = node.text.decode()
        if isinstance(default, Node):
            default = default.text.decode()

        try:
            match node.type:
                case "selector_expression":
                    nodetext = node.text.decode()
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case "identifier":
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case "interpreted_string_literal":
                    value = ast.literal_eval(nodetext)
                case "int_literal":
                    # TODO: hex, octal, binary
                    try:
                        value = int(nodetext)
                    except ValueError:
                        value = nodetext
                case "float_literal":
                    try:
                        value = float(nodetext)
                    except ValueError:
                        value = nodetext
                case "true":
                    value = True
                case "false":
                    value = False
                case "nil":
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
