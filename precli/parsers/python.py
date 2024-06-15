# Copyright 2024 Secure Sauce LLC
import builtins
import codecs
import re
import warnings
from collections import namedtuple

from tree_sitter import Node

from precli.core.call import Call
from precli.core.comparison import Comparison
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers import tokens


Import = namedtuple("Import", "module alias")


class Python(Parser):
    def __init__(self):
        super().__init__("python")
        self.SUPPRESS_COMMENT = re.compile(r"# suppress:? (?P<rules>[^#]+)?#?")
        self.SUPPRESSED_RULES = re.compile(r"(?:(PY\d\d\d|[a-z_]+),?)+")

    def file_extensions(self) -> list[str]:
        return [".py", ".pyw"]

    def rule_prefix(self) -> str:
        return "PY"

    def get_file_encoding(self, file_path):
        with open(file_path, "rb") as f:
            first_two_lines = f.readline() + f.readline()

        encoding_match = re.search(rb"coding[:=]\s*([-\w.]+)", first_two_lines)
        if encoding_match:
            encoding = encoding_match.group(1).decode("ascii")
            try:
                codecs.lookup(encoding)
            except LookupError:
                encoding = "utf-8"
        else:
            encoding = "utf-8"
        return encoding

    def visit_module(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<module>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_statement(self, nodes: list[Node]):
        imps = self.import_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, tokens.IMPORT, value)

    def visit_import_from_statement(self, nodes: list[Node]):
        imps = self.import_from_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, tokens.IMPORT, value)

    def visit_class_definition(self, nodes: list[Node]):
        class_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        cls_name = class_id.string
        self.current_symtab = SymbolTable(cls_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_function_definition(self, nodes: list[Node]):
        func_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        func = func_id.string
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_typed_default_parameter(self, nodes: list[Node]):
        self.visit_typed_parameter(nodes)

    def visit_typed_parameter(self, nodes: list[Node]):
        param_id = self.context["node"].child_by_type(tokens.IDENTIFIER)
        param_type = self.context["node"].child_by_type(tokens.TYPE)

        if param_id is not None and param_type.named_children[0].type in (
            tokens.ATTRIBUTE,
            tokens.IDENTIFIER,
            tokens.STRING,
            tokens.INTEGER,
            tokens.FLOAT,
            tokens.TRUE,
            tokens.FALSE,
            tokens.NONE,
        ):
            param_name = param_id.string
            param_type = self.resolve(
                param_type.named_children[0],
                default=param_type.named_children[0],
            )
            self.current_symtab.put(param_name, tokens.IDENTIFIER, param_type)

        self.visit(nodes)

    def visit_named_expression(self, nodes: list[Node]):
        if len(nodes) > 1 and nodes[1].string == ":=":
            self.visit_assignment(nodes)
        else:
            self.visit(nodes)

    def visit_assignment(self, nodes: list[Node]):
        # pattern_list = expression_list (i.e. HOST, PORT = "", 9999)
        if (
            nodes[0].type == tokens.PATTERN_LIST
            and nodes[2].type == tokens.EXPRESSION_LIST
            and len(nodes[0].named_children) == len(nodes[2].named_children)
        ):
            for i, _ in enumerate(nodes[0].named_children):
                self.visit_assignment(
                    [
                        nodes[0].named_children[i],
                        nodes[1],
                        nodes[2].named_children[i],
                    ]
                )
        elif nodes[0].type == tokens.IDENTIFIER and nodes[2].type in (
            tokens.CALL,
            tokens.ATTRIBUTE,
            tokens.IDENTIFIER,
            tokens.TUPLE,
            tokens.STRING,
            tokens.INTEGER,
            tokens.FLOAT,
            tokens.TRUE,
            tokens.FALSE,
            tokens.NONE,
        ):
            left_hand = self.resolve(nodes[0], default=nodes[0])
            right_hand = self.resolve(nodes[2], default=nodes[2])

            # This is in case a variable is reassigned
            self.current_symtab.put(
                nodes[0].string, tokens.IDENTIFIER, right_hand
            )

            # This is to help full resolution of an attribute/call.
            # This results in two entries in the symtab for this assignment.
            self.current_symtab.put(left_hand, tokens.IDENTIFIER, right_hand)

            if nodes[2].type == tokens.CALL:
                (call_args, call_kwargs) = self.get_func_args(
                    nodes[2].children[1]
                )

                if nodes[2].children:
                    # (attribute | identifier) argument_list
                    func_node = nodes[2].children[0]
                    var_node = self._get_var_node(func_node)
                    ident_node = self._get_func_ident(func_node)
                    arg_list_node = nodes[2].children[1]

                    call = Call(
                        node=nodes[2],
                        name=right_hand,
                        name_qual=right_hand,
                        func_node=func_node,
                        var_node=var_node,
                        ident_node=ident_node,
                        arg_list_node=arg_list_node,
                        args=call_args,
                        kwargs=call_kwargs,
                    )
                    symbol = self.current_symtab.get(left_hand)
                    symbol.push_call(call)

        self.visit(nodes)

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

    def visit_call(self, nodes: list[Node]):
        func_call_qual = self.resolve(nodes[0])
        (func_call_args, func_call_kwargs) = self.get_func_args(nodes[1])

        if self.context["node"].children:
            # (attribute | identifier) argument_list
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
                kwargs=func_call_kwargs,
            )

        if (
            call.name_qualified == "importlib.import_module"
            and self.context["node"].parent.type == tokens.ASSIGNMENT
        ):
            module = self.importlib_import_module(call)
            if module:
                left_hand = self.context["node"].parent.children[0]
                identifier = left_hand.string
                self.current_symtab.remove(identifier)
                self.current_symtab.put(identifier, tokens.IMPORT, module)

        # Suppress re module FutureWarnings. Usually a result of scanning
        # test cases in cpython repo.
        # For example: FutureWarning: Possible set union at position 6
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            self.analyze_node(tokens.CALL, call=call)

        if call.var_node is not None:
            symbol = self.current_symtab.get(call.var_node.string)
            if symbol is not None and symbol.type == tokens.IDENTIFIER:
                symbol.push_call(call)
        else:
            # TODO: why is var_node None?
            pass

        self.visit(nodes)

    def visit_assert(self, nodes: list[Node]):
        self.analyze_node(tokens.ASSERT)
        self.visit(nodes)

    def visit_with_item(self, nodes: list[Node]):
        as_pattern = nodes[0] if nodes[0].type == tokens.AS_PATTERN else None

        if as_pattern is not None and as_pattern.children:
            statement = as_pattern.children[0]
            as_pattern_target = as_pattern.children[2]

            if (
                as_pattern_target.children
                and as_pattern_target.children[0].type == tokens.IDENTIFIER
                and statement.type
                in (tokens.CALL, tokens.ATTRIBUTE, tokens.IDENTIFIER)
            ):
                identifier = as_pattern_target.children[0]
                identifier = self.resolve(identifier, default=identifier)
                statement = self.resolve(statement, default=statement)
                self.current_symtab.put(
                    identifier, tokens.IDENTIFIER, statement
                )

                if as_pattern.children[0].type == tokens.CALL:
                    if as_pattern.children[0].children:
                        # (attribute | identifier) argument_list
                        func_node = as_pattern.children[0].children[0]
                        var_node = self._get_var_node(func_node)
                        ident_node = self._get_func_ident(func_node)
                        arg_list_node = as_pattern.children[0].children[1]

                        call = Call(
                            node=as_pattern.children[0],
                            name=statement,
                            name_qual=statement,
                            func_node=func_node,
                            var_node=var_node,
                            ident_node=ident_node,
                            arg_list_node=arg_list_node,
                        )
                        symbol = self.current_symtab.get(identifier)
                        symbol.push_call(call)

        self.visit(nodes)

    def visit_comparison_operator(self, nodes: list[Node]):
        if len(nodes) > 2:
            left_hand = self.resolve(nodes[0], default=nodes[0])
            operator = nodes[1].string
            right_hand = self.resolve(nodes[2], default=nodes[2])

            comparison = Comparison(
                self.context["node"],
                left_hand=left_hand,
                operator=operator,
                right_hand=right_hand,
            )
            self.analyze_node(
                tokens.COMPARISON_OPERATOR, comparison=comparison
            )
        self.visit(nodes)

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = {}
        for child in nodes:
            if child.type == tokens.DOTTED_NAME:
                imports[child.string] = child.string
            elif child.type == tokens.ALIASED_IMPORT:
                module = child.child_by_type(tokens.DOTTED_NAME)
                alias = child.child_by_type(tokens.IDENTIFIER)
                imports[alias.string] = module.string
        return imports

    def parse_import_statement(self, nodes: list[Node]) -> list:
        imports = []
        for child in nodes:
            if child.type == tokens.DOTTED_NAME:
                plain_import = Import(child.string, None)
                imports.append(plain_import)
            elif child.type == tokens.ALIASED_IMPORT:
                module = child.child_by_type(tokens.DOTTED_NAME)
                alias = child.child_by_type(tokens.IDENTIFIER)
                alias_import = Import(module.string, alias.string)
                imports.append(alias_import)
        return imports

    def unparse_import_statement(self, imports: list) -> str:
        modules = []
        for imp in imports:
            if imp.alias is not None:
                modules.append(f"{imp.module} as {imp.alias}")
            else:
                modules.append(imp.module)
        return f"{tokens.IMPORT} {', '.join(modules)}"

    def import_from_statement(self, nodes: list[Node]) -> dict:
        imports = {}

        from_module = None
        module = nodes[1]
        if module.type == tokens.DOTTED_NAME:
            from_module = module.string
        elif module.type == tokens.RELATIVE_IMPORT:
            # No known way to resolve the relative to absolute
            # However, shouldn't matter much since most rules
            # won't check for local modules.
            from_module = ""

        if nodes[2].type == tokens.IMPORT:
            if nodes[3].type == tokens.WILDCARD_IMPORT:
                # FIXME(ericwb): some modules like Cryptodome permit
                # wildcard imports at various package levels like
                # from Cryptodome import *
                # from Cryptodome.Hash import *
                if f"{from_module}.*" in self.wildcards:
                    for wc in self.wildcards[f"{from_module}.*"]:
                        full_qual = [from_module, wc]
                        imports[wc] = ".".join(filter(None, full_qual))
            else:
                result = self.import_statement(nodes[3:])
                for key, value in result.items():
                    full_qual = [from_module, value]
                    imports[key] = ".".join(filter(None, full_qual))

        return imports

    def parse_import_from_statement(self, nodes: list[Node]) -> tuple:
        package = None
        module = nodes[1]
        if module.type in (tokens.DOTTED_NAME, tokens.RELATIVE_IMPORT):
            package = module.string

        if nodes[2].type == tokens.IMPORT:
            if nodes[3].type == tokens.WILDCARD_IMPORT:
                modules = [Import("*", None)]
            else:
                modules = self.parse_import_statement(nodes[3:])
            return (package, modules)

    def unparse_import_from_statement(self, imports: tuple) -> str:
        package = imports[0]
        modules = []
        for imp in imports[1]:
            if imp.alias is not None:
                modules.append(imp.module + " as " + imp.alias)
            else:
                modules.append(imp.module)
        return f"from {package} import {', '.join(modules)}"

    def importlib_import_module(self, call: Call) -> str:
        name = call.get_argument(position=0, name="name").value_str
        if name is None:
            return None
        package = call.get_argument(position=1, name="package").value_str
        if package is None:
            return name
        subpkg = len(name) - len(name.lstrip(".")) - 1
        package = package.rsplit(".", subpkg)
        return ".".join((package[0], name.lstrip(".")))

    def get_func_args(self, node: Node) -> tuple:
        if node.type != tokens.ARGUMENT_LIST:
            return [], {}

        args = []
        kwargs = {}
        for child in node.named_children:
            if child.type == tokens.KEYWORD_ARGUMENT:
                kwargs |= self.resolve(child)
            else:
                args.append(self.resolve(child, default=child))
        return args, kwargs

    def get_qual_name(self, node: Node) -> Symbol:
        nodetext = node.string
        symbol = self.current_symtab.get(nodetext)
        if symbol is not None:
            return symbol
        if nodetext in dir(builtins):
            return Symbol(nodetext, tokens.IDENTIFIER, nodetext)
        for child in node.children:
            return self.get_qual_name(child)

    def unchain(self, node: Node, result: list):
        """
        Unchain an attribute into its component identifiers skipping
        over argument_list of a call node and such.
        """
        if node.type == tokens.IDENTIFIER:
            result.append(node.string)
        for child in node.named_children:
            if child.type != tokens.ARGUMENT_LIST:
                self.unchain(child, result)

    def resolve(self, node: Node, default=None):
        """
        Resolve the given node into its liternal value.
        """
        nodetext = node.string
        if isinstance(default, Node):
            default = default.string

        try:
            match node.type:
                case tokens.CALL:
                    nodetext = node.children[0].string
                    symbol = self.get_qual_name(node.children[0])
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.ATTRIBUTE:
                    result = []
                    self.unchain(node, result)
                    nodetext = ".".join(result)
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.IDENTIFIER:
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case tokens.KEYWORD_ARGUMENT:
                    keyword = node.named_children[0].string
                    kwvalue = node.named_children[1]
                    value = {keyword: self.resolve(kwvalue, default=kwvalue)}
                case tokens.DICTIONARY:
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case tokens.LIST:
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case tokens.TUPLE:
                    value = ()
                    for child in node.named_children:
                        value += (self.resolve(child),)
                case tokens.STRING:
                    # TODO: handle f-strings? (f"{a}")
                    value = nodetext
                case tokens.INTEGER:
                    # TODO: hex, octal, binary
                    try:
                        value = int(nodetext)
                    except ValueError:
                        value = nodetext
                case tokens.FLOAT:
                    try:
                        value = float(nodetext)
                    except ValueError:
                        value = nodetext
                case tokens.TRUE:
                    value = True
                case tokens.FALSE:
                    value = False
                case tokens.NONE:
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
