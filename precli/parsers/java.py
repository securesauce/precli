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

    def _get_var_node(self, node: Node) -> Node:
        if (
            len(node.named_children) >= 2
            and node.named_children[0].type
            in (tokens.IDENTIFIER, tokens.ATTRIBUTE)
            and node.named_children[1].type == tokens.IDENTIFIER
        ):
            return node.named_children[0]
        elif node.type == tokens.ATTRIBUTE:
            return self._get_var_node(node.named_children[0])

    def _get_func_ident(self, node: Node) -> Node:
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == tokens.ATTRIBUTE:
            return self._get_func_ident(node.named_children[1])
        if node.type == tokens.IDENTIFIER:
            return node

    def visit_method_invocation(self, nodes: list[Node]):
        # TODO: field_access "." identifier argument_list
        #   or
        # identifier "." identifier argument_list
        if nodes[0] != tokens.IDENTIFIER:
            return

        if nodes[2] != tokens.IDENTIFIER:
            return

        obj_name = self.resolve(nodes[0])
        method = nodes[2].text.decode()
        if None in (obj_name, method):
            return

        func_call_qual = ".".join([obj_name, method])
        func_call_args = self.get_func_args(nodes[3])

        # (field_access | identifier) "." identifier argument_list

        call = Call(
            node=self.context["node"],
            name=func_call_qual,
            name_qual=func_call_qual,
            # func_node=func_node, # no equivalent for Java
            var_node=nodes[0],
            ident_node=nodes[2],
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
                case tokens.METHOD_INVOCATION:
                    nodetext = node.children[0].text.decode()
                    symbol = self.get_qual_name(node.children[0])
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.IDENTIFIER:
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.STRING_LITERAL:
                    value = nodetext
                case tokens.CHARACTER_LITERAL:
                    # TODO
                    pass
                case tokens.DECIMAL_INTEGER_LITERAL:
                    try:
                        value = int(nodetext)
                    except ValueError:
                        value = nodetext
                case tokens.HEX_INTEGER_LITERAL:
                    # TODO
                    pass
                case tokens.OCTAL_INTEGER_LITERAL:
                    # TODO
                    pass
                case tokens.DECIMAL_FLOATING_POINT_LITERAL:
                    # TODO
                    pass
                case tokens.BINARY_INTEGER_LITERAL:
                    # TODO
                    pass
                case tokens.TRUE:
                    value = True
                case tokens.FALSE:
                    value = False
                case tokens.NULL_LITERAL:
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
