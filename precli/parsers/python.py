# Copyright 2023 Secure Saurce LLC
import ast

from tree_sitter import Node

from precli.core.parser import Parser
from precli.core.symtab import SymbolTable


class Python(Parser):
    def __init__(self):
        super().__init__("python")

    def file_extension(self) -> str:
        return ".py"

    def visit_module(self, nodes: list[Node]):
        self.current_symtab = SymbolTable()
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
        self.current_symtab = SymbolTable(self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_function_definition(self, nodes: list[Node]):
        self.current_symtab = SymbolTable(self.current_symtab)
        self.visit(nodes)
        self.current_symtab = self.current_symtab.parent()

    def visit_assignment(self, nodes: list[Node]):
        if nodes[0].type == "identifier" and nodes[2].type in (
            "call",
            "attribute",
            "identifier",
        ):
            left_hand = self.literal_value(nodes[0], default=nodes[0])
            right_hand = self.literal_value(nodes[2], default=nodes[2])
            self.current_symtab.put(left_hand, "identifier", right_hand)
        self.visit(nodes)

    def visit_call(self, nodes: list[Node]):
        self.call(nodes)

        if (
            self.context["func_call_qual"] == "importlib.import_module"
            and self.context["node"].parent.type == "assignment"
        ):
            module = self.importlib_import_module(
                self.context["func_call_args"],
                self.context["func_call_kwargs"],
            )
            left_hand = self.context["node"].parent.children[0]
            identifier = left_hand.text.decode()
            self.current_symtab.remove(identifier)
            self.current_symtab.put(identifier, "import", module)

        self.process_rules("call")
        self.context["func_call_qual"] = None
        self.context["func_call_args"] = None
        self.context["func_call_kwargs"] = None

    def visit_with_statement(self, nodes: list[Node]):
        with_clause = nodes[2] if nodes[0].type == "async" else nodes[1]
        with_item = with_clause.children[0]
        as_pattern = with_item.children[0]
        statement = as_pattern.children[0]
        as_pattern_target = as_pattern.children[2]

        if as_pattern_target.children[0].type == "identifier" and (
            statement.type in ("call", "attribute", "identifier")
        ):
            identifier = as_pattern_target.children[0]
            identifier = self.literal_value(identifier, default=identifier)
            statement = self.literal_value(statement, default=statement)
            self.current_symtab.put(identifier, "identifier", statement)
        self.visit(nodes)

    def child_by_type(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.named_children))
        return child[0] if child else None

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = {}
        for child in nodes:
            if child.type == "dotted_name":
                imports[child.text.decode()] = child.text.decode()
            elif child.type == "aliased_import":
                module = self.child_by_type(child, "dotted_name")
                alias = self.child_by_type(child, "identifier")
                imports[alias.text.decode()] = module.text.decode()
        return imports

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

    def importlib_import_module(self, args, kwargs) -> dict:
        name = args[0] if args else kwargs.get("name", None)
        package = args[1] if len(args) > 1 else kwargs.get("package", None)
        if package is None:
            return name
        subpkg = len(name) - len(name.lstrip(".")) - 1
        package = package.rsplit(".", subpkg)
        return ".".join((package[0], name.lstrip(".")))

    def call(self, nodes: list[Node]):
        self.context["func_call_qual"] = self.literal_value(nodes[0])
        (func_call_args, func_call_kwargs) = self.get_func_args(nodes[1])
        self.context["func_call_args"] = func_call_args
        self.context["func_call_kwargs"] = func_call_kwargs

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

    def get_qual_name(self, node: Node) -> tuple:
        symbol = self.current_symtab.get(node.text.decode())
        if symbol is not None:
            return symbol.name, symbol.value
        for child in node.children:
            return self.get_qual_name(child)

    def literal_value(self, node: Node, default=None) -> str:
        value = None
        nodetext = node.text.decode()
        if isinstance(default, Node):
            default = default.text.decode()

        try:
            match node.type:
                case "call":
                    qual_call = self.get_qual_name(node)
                    if qual_call is not None:
                        value = nodetext.replace(qual_call[0], qual_call[1], 1)
                case "attribute":
                    qual_attr = self.get_qual_name(node)
                    if qual_attr is not None:
                        value = nodetext.replace(qual_attr[0], qual_attr[1], 1)
                case "identifier":
                    qual_ident = self.get_qual_name(node)
                    if qual_ident is not None:
                        value = nodetext.replace(
                            qual_ident[0], qual_ident[1], 1
                        )
                case "keyword_argument":
                    keyword = node.named_children[0].text.decode()
                    kwvalue = node.named_children[1]
                    value = {
                        keyword: self.literal_value(kwvalue, default=kwvalue)
                    }
                case "dictionary":
                    value = ast.literal_eval(nodetext)
                case "list":
                    value = ast.literal_eval(nodetext)
                case "tuple":
                    value = ast.literal_eval(nodetext)
                case "string":
                    # TODO: bytes and f-type strings are messed up
                    value = ast.literal_eval(nodetext)
                case "integer":
                    # TODO: hex, octal, binary
                    value = ast.literal_eval(nodetext)
                case "float":
                    value = float(nodetext)
                case "true":
                    value = True
                case "false":
                    value = False
        except ValueError:
            value = None

        return default if value is None else value
