# Copyright 2024 Secure Sauce LLC
import builtins
import codecs
import importlib
import re
import warnings
from collections import namedtuple

from tree_sitter import Node

from precli.core import utils
from precli.core.call import Call
from precli.core.comparison import Comparison
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser
from precli.parsers.node_types import NodeTypes


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

    def get_file_encoding(self, file_contents: str) -> str:
        lines = file_contents.splitlines(keepends=True)
        if len(lines) < 2:
            return "utf-8"

        first_two_lines = lines[0] + lines[1]

        encoding_match = re.search(rb"coding[:=]\s*([-\w.]+)", first_two_lines)
        if not encoding_match:
            return "utf-8"

        encoding = encoding_match.group(1).decode("ascii")
        try:
            codecs.lookup(encoding)
        except LookupError:
            encoding = "utf-8"

        return encoding

    def visit_module(self, nodes: list[Node]):
        self.suppressions = {}
        self.global_symtab = SymbolTable("global")
        self.current_symtab = SymbolTable("<module>")
        self.visit(nodes)
        self.global_symtab = None
        self.current_symtab = self.current_symtab.parent()

    def visit_import_statement(self, nodes: list[Node]):
        imps = self.import_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, NodeTypes.IMPORT, value)
            self.analyze_node(
                self.context["node"].type, package=value, alias=key
            )

    def visit_import_from_statement(self, nodes: list[Node]):
        imps = self.import_from_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, NodeTypes.IMPORT, value)
            self.analyze_node(
                self.context["node"].type, package=value, alias=key
            )

    def visit_class_definition(self, nodes: list[Node]):
        class_id = self.context["node"].child_by_type(NodeTypes.IDENTIFIER)
        cls_name = class_id.string
        self.current_symtab = SymbolTable(cls_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_function_definition(self, nodes: list[Node]):
        func_id = self.context["node"].child_by_type(NodeTypes.IDENTIFIER)
        func = func_id.string
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_typed_default_parameter(self, nodes: list[Node]):
        self.visit_typed_parameter(nodes)

    def visit_typed_parameter(self, nodes: list[Node]):
        param_id = self.context["node"].child_by_type(NodeTypes.IDENTIFIER)
        param_type = self.context["node"].child_by_type(NodeTypes.TYPE)

        if param_id is not None and param_type.named_children[0].type in (
            NodeTypes.ATTRIBUTE,
            NodeTypes.IDENTIFIER,
            NodeTypes.STRING,
            NodeTypes.INTEGER,
            NodeTypes.FLOAT,
            NodeTypes.TRUE,
            NodeTypes.FALSE,
            NodeTypes.NONE,
        ):
            param_name = param_id.string
            param_type = self.resolve(
                param_type.named_children[0],
                default=param_type.named_children[0],
            )
            self.current_symtab.put(
                param_name, NodeTypes.IDENTIFIER, param_type
            )

        self.visit(nodes)

    def visit_named_expression(self, nodes: list[Node]):
        if len(nodes) > 1 and nodes[1].string == ":=":
            self.visit_assignment(nodes)
        else:
            self.visit(nodes)

    def visit_augmented_assignment(self, nodes: list[Node]):
        left_hand = nodes[0].string
        symbol = self.current_symtab.get(left_hand)
        if symbol is not None and isinstance(symbol.value, int):
            if nodes[0].type == NodeTypes.IDENTIFIER and nodes[2].type in (
                NodeTypes.PARENTHESIZED_EXPRESSION,
                NodeTypes.ATTRIBUTE,
                NodeTypes.IDENTIFIER,
                NodeTypes.BINARY_OPERATOR,
                NodeTypes.UNARY_OPERATOR,
                NodeTypes.INTEGER,
                NodeTypes.TRUE,
                NodeTypes.FALSE,
            ):
                right_hand = self.resolve(nodes[2], default=nodes[2])
                if isinstance(right_hand, int):
                    if nodes[1].string == "&=":
                        value = symbol.value & right_hand
                        self.current_symtab.put(
                            left_hand, NodeTypes.IDENTIFIER, value
                        )
                    elif nodes[1].string == "|=":
                        value = symbol.value | right_hand
                        self.current_symtab.put(
                            left_hand, NodeTypes.IDENTIFIER, value
                        )

        self.visit(nodes)

    def visit_assignment(self, nodes: list[Node]):
        # pattern_list = expression_list (i.e. HOST, PORT = "", 9999)
        if (
            nodes[0].type == NodeTypes.PATTERN_LIST
            and nodes[2].type == NodeTypes.EXPRESSION_LIST
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
        elif nodes[0].type == NodeTypes.IDENTIFIER and nodes[2].type in (
            NodeTypes.PARENTHESIZED_EXPRESSION,
            NodeTypes.CALL,
            NodeTypes.ATTRIBUTE,
            NodeTypes.IDENTIFIER,
            NodeTypes.DICTIONARY,
            NodeTypes.TUPLE,
            NodeTypes.BINARY_OPERATOR,
            NodeTypes.UNARY_OPERATOR,
            NodeTypes.STRING,
            NodeTypes.INTEGER,
            NodeTypes.FLOAT,
            NodeTypes.TRUE,
            NodeTypes.FALSE,
            NodeTypes.NONE,
        ):
            left_hand = nodes[0].string
            right_hand = self.resolve(nodes[2], default=nodes[2])

            self.current_symtab.put(
                left_hand, NodeTypes.IDENTIFIER, right_hand
            )

            if nodes[2].type == NodeTypes.CALL:
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

    def _get_var_node(self, node: Node) -> Node | None:
        if (
            len(node.named_children) >= 2
            and node.named_children[0].type
            in (NodeTypes.IDENTIFIER, NodeTypes.ATTRIBUTE)
            and node.named_children[1].type == NodeTypes.IDENTIFIER
        ):
            return node.named_children[0]
        elif node.type == NodeTypes.ATTRIBUTE:
            return self._get_var_node(node.named_children[0])

    def _get_func_ident(self, node: Node) -> Node | None:
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == NodeTypes.ATTRIBUTE:
            return self._get_func_ident(node.named_children[1])
        if node.type == NodeTypes.IDENTIFIER:
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
            and self.context["node"].parent.type == NodeTypes.ASSIGNMENT
        ):
            module = self.importlib_import_module(call)
            if module:
                left_hand = self.context["node"].parent.children[0]
                identifier = left_hand.string
                self.current_symtab.remove(identifier)
                self.current_symtab.put(identifier, NodeTypes.IMPORT, module)
        elif call.name_qualified == "socket.setdefaulttimeout":
            # Keep track of the global timeout in case it has been set. If
            # it has a postive value, the timeout related rules should not
            # return a result.
            timeout = call.get_argument(position=0, name="timeout").value
            self.global_symtab.put(
                "GLOBAL_DEFAULT_TIMEOUT", NodeTypes.IDENTIFIER, timeout
            )

        # Suppress re module FutureWarnings. Usually a result of scanning
        # test cases in cpython repo.
        # For example: FutureWarning: Possible set union at position 6
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            self.analyze_node(NodeTypes.CALL, call=call)

        if call.var_node is not None:
            symbol = self.current_symtab.get(call.var_node.string)
            if symbol is not None and symbol.type == NodeTypes.IDENTIFIER:
                symbol.push_call(call)
        else:
            # TODO: why is var_node None?
            pass

        self.visit(nodes)

    def visit_assert(self, nodes: list[Node]):
        self.analyze_node(NodeTypes.ASSERT)
        self.visit(nodes)

    def visit_with_item(self, nodes: list[Node]):
        as_pattern = (
            nodes[0] if nodes[0].type == NodeTypes.AS_PATTERN else None
        )

        if as_pattern is not None and as_pattern.children:
            statement = as_pattern.children[0]
            as_pattern_target = as_pattern.children[2]

            if (
                as_pattern_target.children
                and as_pattern_target.children[0].type == NodeTypes.IDENTIFIER
                and statement.type
                in (NodeTypes.CALL, NodeTypes.ATTRIBUTE, NodeTypes.IDENTIFIER)
            ):
                identifier = as_pattern_target.children[0]
                identifier = self.resolve(identifier, default=identifier)
                statement = self.resolve(statement, default=statement)
                self.current_symtab.put(
                    identifier, NodeTypes.IDENTIFIER, statement
                )

                if as_pattern.children[0].type == NodeTypes.CALL:
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
                NodeTypes.COMPARISON_OPERATOR, comparison=comparison
            )
        self.visit(nodes)

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = {}
        for child in nodes:
            if child.type == NodeTypes.DOTTED_NAME:
                imports[child.string] = child.string
            elif child.type == NodeTypes.ALIASED_IMPORT:
                module = child.child_by_type(NodeTypes.DOTTED_NAME)
                alias = child.child_by_type(NodeTypes.IDENTIFIER)
                imports[alias.string] = module.string
        return imports

    def parse_import_statement(self, nodes: list[Node]) -> list:
        imports = []
        for child in nodes:
            if child.type == NodeTypes.DOTTED_NAME:
                plain_import = Import(child.string, None)
                imports.append(plain_import)
            elif child.type == NodeTypes.ALIASED_IMPORT:
                module = child.child_by_type(NodeTypes.DOTTED_NAME)
                alias = child.child_by_type(NodeTypes.IDENTIFIER)
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
        return f"{NodeTypes.IMPORT} {', '.join(modules)}"

    def import_from_statement(self, nodes: list[Node]) -> dict:
        imports = {}

        package = None
        if nodes[1].type == NodeTypes.DOTTED_NAME:
            package = nodes[1].string
        elif nodes[1].type == NodeTypes.RELATIVE_IMPORT:
            # No known way to resolve the relative to absolute
            # However, shouldn't matter much since most rules
            # won't check for local modules.
            package = ""

        if nodes[2].type == NodeTypes.IMPORT:
            if nodes[3].type == NodeTypes.WILDCARD_IMPORT:
                try:
                    module = importlib.import_module(package)
                    for symbol in dir(module):
                        if not symbol.startswith("_"):
                            full_qual = [package, symbol]
                            imports[symbol] = ".".join(filter(None, full_qual))
                except (ModuleNotFoundError, ValueError):
                    # FIXME(ericwb): some modules like Cryptodome permit
                    # wildcard imports at various package levels like
                    # from Cryptodome import *
                    # from Cryptodome.Hash import *
                    if f"{package}.*" in self.wildcards:
                        for module in self.wildcards[f"{package}.*"]:
                            full_qual = [package, module]
                            imports[module] = ".".join(filter(None, full_qual))
            else:
                result = self.import_statement(nodes[3:])
                for key, value in result.items():
                    full_qual = [package, value]
                    imports[key] = ".".join(filter(None, full_qual))

        return imports

    def parse_import_from_statement(self, nodes: list[Node]) -> tuple:
        package = None
        module = nodes[1]
        if module.type in (NodeTypes.DOTTED_NAME, NodeTypes.RELATIVE_IMPORT):
            package = module.string

        if nodes[2].type == NodeTypes.IMPORT:
            if nodes[3].type == NodeTypes.WILDCARD_IMPORT:
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

    def importlib_import_module(self, call: Call) -> str | None:
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
        if node.type != NodeTypes.ARGUMENT_LIST:
            return [], {}

        args = []
        kwargs = {}
        for child in node.named_children:
            if child.type == NodeTypes.KEYWORD_ARGUMENT:
                kwargs |= self.resolve(child)
            else:
                args.append(self.resolve(child, default=child))
        return args, kwargs

    def get_qual_name(self, node: Node) -> Symbol | None:
        nodetext = node.string
        symbol = self.current_symtab.get(nodetext)
        if symbol is not None:
            return symbol
        if nodetext in dir(builtins):
            return Symbol(nodetext, NodeTypes.IDENTIFIER, nodetext)
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
            match node.type:
                case NodeTypes.PARENTHESIZED_EXPRESSION:
                    if len(node.named_children) == 1:
                        value = self.resolve(node.named_children[0])
                case NodeTypes.CALL:
                    nodetext = node.children[0].string
                    symbol = self.get_qual_name(node.children[0])
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case NodeTypes.ATTRIBUTE:
                    result = []
                    self.unchain(node, result)
                    nodetext = ".".join(result)
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case NodeTypes.IDENTIFIER:
                    symbol = self.get_qual_name(node)
                    if symbol is not None:
                        value = self.join_symbol(nodetext, symbol)
                case NodeTypes.KEYWORD_ARGUMENT:
                    keyword = node.named_children[0].string
                    kwvalue = node.named_children[1]
                    value = {keyword: self.resolve(kwvalue, default=kwvalue)}
                case NodeTypes.DICTIONARY:
                    value = {}
                    for child in node.named_children:
                        if child.type == NodeTypes.PAIR:
                            keyword = utils.to_str(
                                child.named_children[0].string
                            )
                            kwvalue = child.named_children[1]
                            value[keyword] = self.resolve(
                                kwvalue, default=kwvalue
                            )
                case NodeTypes.SUBSCRIPT:
                    # TODO: fix other subscript usage like list, slice, etc?
                    var = self.resolve(node.named_children[0])
                    if (
                        var is not None
                        and isinstance(var, dict)
                        or isinstance(var, tuple)
                    ):
                        key = node.named_children[1]
                        try:
                            if key.type == NodeTypes.STRING:
                                value = var[utils.to_str(self.resolve(key))]
                            elif key.type == NodeTypes.INTEGER:
                                value = var[self.resolve(key)]
                        except KeyError:
                            pass
                case NodeTypes.LIST:
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case NodeTypes.TUPLE:
                    value = ()
                    for child in node.named_children:
                        value += (self.resolve(child),)
                case NodeTypes.UNARY_OPERATOR:
                    # unary_operator: (+, -, ~) attribute
                    old_value = self.resolve(node.children[1])
                    if isinstance(old_value, int):
                        if node.children[0].string == "+":
                            value = +old_value
                        elif node.children[0].string == "-":
                            value = -old_value
                        elif node.children[0].string == "~":
                            value = ~old_value
                case NodeTypes.BINARY_OPERATOR:
                    # binary_operator (|, &) attribute
                    left = self.resolve(node.children[0])
                    right = self.resolve(node.children[2])

                    if isinstance(left, int) and isinstance(right, int):
                        if node.children[1].string == "|":
                            value = left | right
                        elif node.children[1].string == "&":
                            value = left & right
                case NodeTypes.STRING:
                    # TODO: handle f-strings? (f"{a}")
                    value = nodetext
                case NodeTypes.INTEGER:
                    if nodetext.lower().startswith("0x"):
                        base = 16
                    elif nodetext.lower().startswith("0o"):
                        base = 8
                    elif nodetext.lower().startswith("0b"):
                        base = 2
                    else:
                        base = 10
                    try:
                        value = int(nodetext, base)
                    except ValueError:
                        value = nodetext
                case NodeTypes.FLOAT:
                    try:
                        value = float(nodetext)
                    except ValueError:
                        value = nodetext
                case NodeTypes.TRUE:
                    value = True
                case NodeTypes.FALSE:
                    value = False
                case NodeTypes.NONE:
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
