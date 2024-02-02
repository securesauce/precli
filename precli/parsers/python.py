# Copyright 2024 Secure Saurce LLC
import builtins
import re
from collections import namedtuple

from tree_sitter import Node

from precli.core.call import Call
from precli.core.comparison import Comparison
from precli.core.symtab import Symbol
from precli.core.symtab import SymbolTable
from precli.parsers import Parser


Import = namedtuple("Import", "module alias")


class Python(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("python", enabled, disabled)
        self.SUPPRESS_COMMENT = re.compile(r"# suppress:? (?P<rules>[^#]+)?#?")
        self.SUPPRESSED_RULES = re.compile(r"(?:(PY\d\d\d|[a-z_]+),?)+")

    def visit_module(self, nodes: list[Node]):
        self.suppressions = {}
        self.current_symtab = SymbolTable("<module>")
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_import_statement(self, nodes: list[Node]):
        imps = self.import_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, "import", value)

    def visit_import_from_statement(self, nodes: list[Node]):
        imps = self.import_from_statement(nodes)
        for key, value in imps.items():
            self.current_symtab.put(key, "import", value)

    def visit_class_definition(self, nodes: list[Node]):
        class_id = self.first_match(self.context["node"], "identifier")
        cls_name = class_id.text.decode()
        self.current_symtab = SymbolTable(cls_name, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_function_definition(self, nodes: list[Node]):
        func_id = self.first_match(self.context["node"], "identifier")
        func = func_id.text.decode()
        self.current_symtab = SymbolTable(func, parent=self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_named_expression(self, nodes: list[Node]):
        if len(nodes) > 1 and nodes[1].text.decode() == ":=":
            self.visit_assignment(nodes)
        else:
            self.visit(nodes)

    def visit_assignment(self, nodes: list[Node]):
        if nodes[0].type == "identifier" and nodes[2].type in (
            "call",
            "attribute",
            "identifier",
            "integer",
            "float",
            "true",
            "false",
            "none",
        ):
            left_hand = self.literal_value(nodes[0], default=nodes[0])
            right_hand = self.literal_value(nodes[2], default=nodes[2])
            self.current_symtab.put(left_hand, "identifier", right_hand)
            if nodes[2].type == "call":
                (call_args, call_kwargs) = self.get_func_args(
                    nodes[2].children[1]
                )
                call = Call(
                    node=nodes[2],
                    name=right_hand,
                    name_qual=right_hand,
                    args=call_args,
                    kwargs=call_kwargs,
                )
                symbol = self.current_symtab.get(left_hand)
                symbol.push_call(call)

        self.visit(nodes)

    def visit_call(self, nodes: list[Node]):
        func_call_qual = self.literal_value(nodes[0])
        (func_call_args, func_call_kwargs) = self.get_func_args(nodes[1])

        call = Call(
            node=self.context["node"],
            name=func_call_qual,
            name_qual=func_call_qual,
            args=func_call_args,
            kwargs=func_call_kwargs,
        )

        if (
            call.name_qualified == "importlib.import_module"
            and self.context["node"].parent.type == "assignment"
        ):
            module = self.importlib_import_module(call)
            left_hand = self.context["node"].parent.children[0]
            identifier = left_hand.text.decode()
            self.current_symtab.remove(identifier)
            self.current_symtab.put(identifier, "import", module)

        self.process_rules("call", call=call)

        if call.var_node is not None:
            symbol = self.current_symtab.get(call.var_node.text.decode())
            if symbol is not None and symbol.type == "identifier":
                symbol.push_call(call)
        else:
            # TODO: why is var_node None?
            pass

        self.visit(nodes)

    def visit_with_item(self, nodes: list[Node]):
        as_pattern = nodes[0] if nodes[0].type == "as_pattern" else None

        if as_pattern is not None:
            statement = as_pattern.children[0]
            as_pattern_target = as_pattern.children[2]

            if as_pattern_target.children[0].type == "identifier" and (
                statement.type in ("call", "attribute", "identifier")
            ):
                identifier = as_pattern_target.children[0]
                identifier = self.literal_value(identifier, default=identifier)
                statement = self.literal_value(statement, default=statement)
                self.current_symtab.put(identifier, "identifier", statement)

                if as_pattern.children[0].type == "call":
                    call = Call(
                        node=as_pattern.children[0],
                        name=statement,
                        name_qual=statement,
                    )
                    symbol = self.current_symtab.get(identifier)
                    symbol.push_call(call)

        self.visit(nodes)

    def visit_comparison_operator(self, nodes: list[Node]):
        if len(nodes) > 2:
            left_hand = self.literal_value(nodes[0], default=nodes[0])
            operator = nodes[1].text.decode()
            right_hand = self.literal_value(nodes[2], default=nodes[2])

            comparison = Comparison(
                self.context["node"],
                left_hand=left_hand,
                operator=operator,
                right_hand=right_hand,
            )
            self.process_rules("comparison_operator", comparison=comparison)
        self.visit(nodes)

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = {}
        for child in nodes:
            if child.type == "dotted_name":
                imports[child.text.decode()] = child.text.decode()
            elif child.type == "aliased_import":
                module = self.first_match(child, "dotted_name")
                alias = self.first_match(child, "identifier")
                imports[alias.text.decode()] = module.text.decode()
        return imports

    def parse_import_statement(self, nodes: list[Node]) -> list:
        imports = []
        for child in nodes:
            if child.type == "dotted_name":
                plain_import = Import(child.text.decode(), None)
                imports.append(plain_import)
            elif child.type == "aliased_import":
                module = self.first_match(child, "dotted_name").text
                alias = self.first_match(child, "identifier").text
                alias_import = Import(module.decode(), alias.decode())
                imports.append(alias_import)
        return imports

    def unparse_import_statement(self, imports: list) -> str:
        modules = []
        for imp in imports:
            if imp.alias is not None:
                modules.append(imp.module + " as " + imp.alias)
            else:
                modules.append(imp.module)
        return f"import {', '.join(modules)}"

    def import_from_statement(self, nodes: list[Node]) -> dict:
        imports = {}

        module = nodes[1]
        if module.type == "dotted_name":
            from_module = module.text.decode()
        elif module.type == "relative_import":
            # No known way to resolve the relative to absolute
            # However, shouldn't matter much since most rules
            # won't check for local modules.
            from_module = ""

        if nodes[2].type == "import":
            if nodes[3].type == "wildcard_import":
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
        module = nodes[1]
        if module.type == "dotted_name":
            package = module.text.decode()
        elif module.type == "relative_import":
            package = module.text.decode()

        if nodes[2].type == "import":
            if nodes[3].type == "wildcard_import":
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

    def importlib_import_module(self, call: Call) -> dict:
        name = call.get_argument(position=0, name="name").value
        package = call.get_argument(position=1, name="package").value
        if package is None:
            return name
        subpkg = len(name) - len(name.lstrip(".")) - 1
        package = package.rsplit(".", subpkg)
        return ".".join((package[0], name.lstrip(".")))

    def get_func_args(self, node: Node) -> tuple:
        if node.type != "argument_list":
            return [], {}

        args = []
        kwargs = {}
        for child in node.named_children:
            if child.type == "keyword_argument":
                kwargs |= self.literal_value(child)
            else:
                args.append(self.literal_value(child, default=child))
        return args, kwargs

    def get_qual_name(self, node: Node) -> Symbol:
        nodetext = node.text.decode()
        symbol = self.current_symtab.get(nodetext)
        if symbol is not None:
            return symbol
        if nodetext in dir(builtins):
            return Symbol(nodetext, "identifier", nodetext)
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
                case "call":
                    nodetext = node.children[0].text.decode()
                    symbol = self.get_qual_name(node.children[0])
                    if symbol is not None:
                        if isinstance(symbol.value, str):
                            value = nodetext.replace(
                                symbol.name, symbol.value, 1
                            )
                        else:
                            value = symbol.value
                case "attribute":
                    result = []
                    self.unchain(node, result)
                    nodetext = ".".join(result)
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
                case "keyword_argument":
                    keyword = node.named_children[0].text.decode()
                    kwvalue = node.named_children[1]
                    value = {
                        keyword: self.literal_value(kwvalue, default=kwvalue)
                    }
                case "dictionary":
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case "list":
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case "tuple":
                    # TODO: don't use ast.literal_eval
                    # value = ast.literal_eval(nodetext)
                    pass
                case "string":
                    # TODO: handle byte strings (b"abc")
                    # TODO: handle f-strings? (f"{a}")
                    if nodetext.startswith('"""') or nodetext.startswith(
                        "'''"
                    ):
                        value = nodetext[3:-3]
                    elif nodetext.startswith('"') or nodetext.startswith("'"):
                        value = nodetext[1:-1]
                case "integer":
                    # TODO: hex, octal, binary
                    try:
                        value = int(nodetext)
                    except ValueError:
                        value = nodetext
                case "float":
                    try:
                        value = float(nodetext)
                    except ValueError:
                        value = nodetext
                case "true":
                    value = True
                case "false":
                    value = False
                case "none":
                    value = None
        except ValueError:
            value = None

        return default if "value" not in vars() else value
