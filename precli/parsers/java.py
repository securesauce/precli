# Copyright 2024 Secure Sauce LLC
import re

from tree_sitter import Node

from precli.core.call import Call
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers import tokens


class Java(Parser):
    def __init__(self):
        super().__init__("java")
        self.SUPPRESS_COMMENT = re.compile(
            r"// suppress:? (?P<rules>[^#]+)?#?"
        )
        self.SUPPRESSED_RULES = re.compile(r"(?:(JAV\d\d\d|[a-z_]+),?)+")

    def file_extensions(self) -> list[str]:
        return [".java"]

    def rule_prefix(self) -> str:
        return "JAV"

    def get_file_encoding(self, file_path: str) -> str:
        return "utf-8"

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
            wc_import = nodes[1].string

            if f"{wc_import}.*" in self.wildcards:
                for wc in self.wildcards[f"{wc_import}.*"]:
                    full_import = ".".join(filter(None, [wc_import, wc]))
                    self.current_symtab.put(wc, tokens.IMPORT, full_import)
        else:
            # "import" scoped_identifier ";"
            package = nodes[1].string
            symbol = package.split(".")[-1]
            self.current_symtab.put(symbol, tokens.IMPORT, package)

    def visit_class_declaration(self, nodes: list[Node]):
        class_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        cls_name = class_id.string
        self.current_symtab = SymbolTable(cls_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_interface_declaration(self, nodes: list[Node]):
        if_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        if_name = if_id.string
        self.current_symtab = SymbolTable(if_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_annotation_type_declaration(self, nodes: list[Node]):
        anno_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        ann_name = anno_id.string
        self.current_symtab = SymbolTable(ann_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_enum_declaration(self, nodes: list[Node]):
        enum_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        e_name = enum_id.string
        self.current_symtab = SymbolTable(e_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_constructor_declaration(self, nodes: list[Node]):
        const_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        cst_name = const_id.string
        self.current_symtab = SymbolTable(cst_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_record_declaration(self, nodes: list[Node]):
        record_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        rec_name = record_id.string
        self.current_symtab = SymbolTable(rec_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_method_declaration(self, nodes: list[Node]):
        method_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        mth_name = method_id.string
        self.current_symtab = SymbolTable(mth_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def _get_var_node(self, node: Node) -> Node | None:
        if (
            len(node.named_children) >= 2
            and node.named_children[0].type
            in (tokens.IDENTIFIER, tokens.ATTRIBUTE)
            and node.named_children[1].type == tokens.IDENTIFIER
        ):
            return node.named_children[0]
        elif node.type == tokens.ATTRIBUTE:
            return self._get_var_node(node.named_children[0])

    def _get_func_ident(self, node: Node) -> Node | None:
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == tokens.ATTRIBUTE:
            return self._get_func_ident(node.named_children[1])
        if node.type == tokens.IDENTIFIER:
            return node

    def visit_local_variable_declaration(self, nodes: list[Node]):
        # type_identifier variable_declarator
        if nodes[0].type not in (
            tokens.TYPE_IDENTIFIER,
            tokens.SCOPED_TYPE_IDENTIFIER,
        ):
            return
        if nodes[1].type != tokens.VARIABLE_DECLARATOR:
            return

        var_nodes = nodes[1].named_children

        if (
            len(var_nodes) > 1
            and var_nodes[0].type
            in (
                tokens.IDENTIFIER,
                tokens.SCOPED_TYPE_IDENTIFIER,
            )
            and var_nodes[1].type
            in (
                tokens.OBJECT_CREATION_EXPRESSION,
                tokens.METHOD_INVOCATION,
                tokens.ATTRIBUTE,
                tokens.IDENTIFIER,
                tokens.STRING_LITERAL,
                tokens.CHARACTER_LITERAL,
                tokens.DECIMAL_INTEGER_LITERAL,
                tokens.HEX_INTEGER_LITERAL,
                tokens.OCTAL_INTEGER_LITERAL,
                tokens.DECIMAL_FLOATING_POINT_LITERAL,
                tokens.BINARY_INTEGER_LITERAL,
                tokens.TRUE,
                tokens.FALSE,
                tokens.NULL_LITERAL,
            )
        ):
            left_hand = self.resolve(var_nodes[0], default=var_nodes[0])
            right_hand = self.resolve(var_nodes[1], default=var_nodes[1])

            # This is in case a variable is reassigned
            self.current_symtab.put(
                var_nodes[0].string, tokens.IDENTIFIER, right_hand
            )

            # This is to help full resolution of an attribute/call.
            # This results in two entries in the symtab for this assignment.
            self.current_symtab.put(left_hand, tokens.IDENTIFIER, right_hand)

            if var_nodes[1].type == tokens.METHOD_INVOCATION:
                call = self.method_call(var_nodes[1], right_hand)
                symbol = self.current_symtab.get(left_hand)
                symbol.push_call(call)

        self.visit(nodes)

    def visit_object_creation_expression(self, nodes: list[Node]):
        if nodes[0].type != "new":
            return

        if nodes[1].type not in (
            tokens.TYPE_IDENTIFIER,
            tokens.SCOPED_TYPE_IDENTIFIER,
        ):
            return

        # "new" (type_identifier | scoped_type_identifier) argument_list

        cls_name = self.resolve(nodes[1])
        if cls_name is None:
            return
        func_call_qual = cls_name

        call = self.method_call(self.context["node"], func_call_qual)
        self.analyze_node(tokens.OBJECT_CREATION_EXPRESSION, call=call)

        self.visit(nodes)

    def visit_method_invocation(self, nodes: list[Node]):
        if nodes[0].type not in (tokens.FIELD_ACCESS, tokens.IDENTIFIER):
            return

        if nodes[1].type == "." and nodes[2].type == tokens.IDENTIFIER:
            # (field_access | identifier) "." identifier argument_list
            obj_name = self.resolve(nodes[0])
            method = nodes[2].string
            if None in (obj_name, method):
                return
            func_call_qual = ".".join([obj_name, method])
        else:
            # identifier argument_list
            method_name = self.resolve(nodes[0])
            if method_name is None:
                return
            func_call_qual = method_name

        call = self.method_call(self.context["node"], func_call_qual)
        self.analyze_node(tokens.METHOD_INVOCATION, call=call)

        symbol = self.current_symtab.get(call.var_node.string)
        if symbol is not None and symbol.type == tokens.IDENTIFIER:
            symbol.push_call(call)

        self.visit(nodes)

    def method_call(self, node: Node, func_call_qual: str):
        if (
            node.children[1].type == "."
            and node.children[2].type == tokens.IDENTIFIER
        ):
            # (field_access | identifier) "." identifier argument_list
            func_node = None
            obj_node = node.children[0]
            method_node = node.children[2]
        elif node.children[1].type in (
            tokens.TYPE_IDENTIFIER,
            tokens.SCOPED_TYPE_IDENTIFIER,
        ):
            # "new" (type_identifier | scoped_type_identifier) argument_list
            func_node = node.children[1]
            # TODO: get the obj_node and method_node from func_node
            obj_node = None
            method_node = None
        else:
            # identifier argument_list
            func_node = None
            obj_node = node.children[0]
            method_node = node.children[0]

        arg_list_node = node.child_by_type(tokens.ARGUMENT_LIST)
        call_args = self.get_func_args(arg_list_node)

        return Call(
            node=node,
            name=func_call_qual,
            name_qual=func_call_qual,
            func_node=func_node,
            var_node=obj_node,
            ident_node=method_node,
            arg_list_node=arg_list_node,
            args=call_args,
        )

    def get_func_args(self, node: Node) -> list:
        if node.type != tokens.ARGUMENT_LIST:
            return []

        args = []
        for child in node.named_children:
            args.append(self.resolve(child, default=child))

        return args

    def get_qual_name(self, node: Node) -> Symbol | None:
        nodetext = node.string
        symbol = self.current_symtab.get(nodetext)

        if symbol is not None:
            return symbol
        for child in node.children:
            return self.get_qual_name(child)

    def resolve(self, node: Node, default=None):
        """
        Resolve the given node into its liternal value.
        """
        nodetext = node.string
        if isinstance(default, Node):
            default = default.string

        try:
            match node.type:
                case tokens.OBJECT_CREATION_EXPRESSION:
                    # "new" (type_identifier | scoped_type_identifier)
                    # argument_list
                    if node.children[0].type == "new" and node.children[
                        1
                    ].type in (
                        tokens.TYPE_IDENTIFIER,
                        tokens.SCOPED_TYPE_IDENTIFIER,
                    ):
                        nodetext = node.children[1].string
                        if (
                            node.children[1].type
                            == tokens.SCOPED_TYPE_IDENTIFIER
                        ):
                            symbol = Symbol(
                                nodetext, tokens.IDENTIFIER, nodetext
                            )
                        else:
                            symbol = self.get_qual_name(node.children[1])
                        if symbol is not None:
                            value = self.join_symbol(nodetext, symbol)
                case tokens.METHOD_INVOCATION:
                    if (
                        node.children[1].type == "."
                        and node.children[2].type == tokens.IDENTIFIER
                    ):
                        # (field_access | identifier) "." identifier
                        # argument_list
                        part1 = node.children[0].string
                        part2 = node.children[2].string
                        nodetext = ".".join([part1, part2])
                    else:
                        # identifier argument_list
                        nodetext = node.children[0].string
                    symbol = self.get_qual_name(node.children[0])
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.FIELD_ACCESS:
                    symbol = Symbol(nodetext, tokens.IDENTIFIER, nodetext)
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
