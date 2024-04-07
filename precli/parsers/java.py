# Copyright 2024 Secure Saurce LLC
import re

from tree_sitter import Node

from precli.core.call import Call
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers import tokens


class Java(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("java", enabled, disabled)
        self.SUPPRESS_COMMENT = re.compile(
            r"// suppress:? (?P<rules>[^#]+)?#?"
        )
        self.SUPPRESSED_RULES = re.compile(r"(?:(JAV\d\d\d|[a-z_]+),?)+")

    def file_extensions(self) -> list[str]:
        return [".java"]

    def visit_program(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<program>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_declaration(self, nodes: list[Node]):
        if nodes[0].type != tokens.IMPORT:
            return

        if nodes[1].type != tokens.SCOPED_IDENTIFIER:
            return

        if len(nodes) > 3 and nodes[3].type == tokens.ASTERISK:
            # "import" scoped_identifier "." asterisk ";"
            wc_import = nodes[1].text.decode()

            if f"{wc_import}.*" in self.wildcards:
                for wc in self.wildcards[f"{wc_import}.*"]:
                    full_import = ".".join(filter(None, [wc_import, wc]))
                    self.current_symtab.put(wc, tokens.IMPORT, full_import)
        else:
            # "import" scoped_identifier ";"
            package = nodes[1].text.decode()
            symbol = package.split(".")[-1]
            self.current_symtab.put(symbol, tokens.IMPORT, package)

    def visit_method_invocation(self, nodes: list[Node]):
        # field_access "." identifier argument_list
        #   or
        # identifier "." identifier argument_list
        if nodes[0] != tokens.IDENTIFIER:
            return

        if nodes[2] != tokens.IDENTIFIER:
            return

        class_name = self.resolve(nodes[0])
        method = nodes[2].text.decode()
        if None in (class_name, method):
            return

        func_call_qual = ".".join([class_name, method])
        func_call_args = self.get_func_args(nodes[3])

        call = Call(
            node=self.context["node"],
            name=func_call_qual,
            name_qual=func_call_qual,
            arg_list_node=nodes[3],
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

    def resolve(self, node: Node, default=None):
        """
        Resolve the given node into its liternal value.
        """
        nodetext = node.text.decode()
        if isinstance(default, Node):
            default = default.text.decode()

        try:
            match node.type:
                # TODO: case.tokens.CALL:
                case tokens.IDENTIFIER:
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case tokens.STRING_LITERAL:
                    value = nodetext
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
                case tokens.NULL_LITERAL:
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
