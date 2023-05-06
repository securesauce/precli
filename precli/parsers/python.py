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
        if nodes[0].type == "identifier":
            left_hand = self.literal_value(nodes[0])
            right_hand = nodes[2]
            self.current_symtab.put(left_hand, "identifier", right_hand)
        self.visit(nodes)

    def visit_call(self, nodes: list[Node]):
        self.call(nodes)
        self.exec_rules("call")
        self.context["func_call_qual"] = None
        self.context["func_call_args"] = None
        self.context["func_call_kwargs"] = None

    def child_by_type(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.children))
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

    def call(self, nodes: list[Node]):
        # Resolve the fully qualified function name
        # TODO(ericwb): just use literal_value?
        func_call_qual = self.get_qual_name(nodes[0])
        if func_call_qual is not None:
            func_call_qual = (
                nodes[0]
                .text.decode()
                .replace(func_call_qual[0], func_call_qual[1], 1)
            )
        self.context["func_call_qual"] = func_call_qual

        # Get the arguments of the function call
        (func_call_args, func_call_kwargs) = self.get_func_args(nodes[1])
        self.context["func_call_args"] = func_call_args
        self.context["func_call_kwargs"] = func_call_kwargs

    def get_func_args(self, node: Node) -> tuple:
        if node.type != "argument_list":
            return [], {}

        args = []
        kwargs = {}
        for child in node.named_children:
            # TODO: can this just pass to literal_value
            if child.type == "keyword_argument":
                keyword = child.children[0].text.decode()
                kwargs[keyword] = self.literal_value(child.children[2])
            else:
                arg = self.literal_value(child)
                args.append(arg)
        return args, kwargs

    def get_qual_name(self, node: Node) -> tuple:
        symbol = self.current_symtab.get(node.text.decode())
        if symbol is not None:
            if symbol.type == "import":
                return symbol.name, symbol.value
            if symbol.type == "identifier":
                if symbol.value.type == "call":
                    attribute = symbol.value.children[0]
                    arguments = symbol.value.children[1]
                    function = self.literal_value(attribute)
                    if function == "importlib.import_module":
                        (args, kwargs) = self.get_func_args(arguments)
                        name = args[0] if args else kwargs.get("name", None)
                        return symbol.name, name
                    return symbol.name, self.literal_value(symbol.value)
                elif symbol.value.type == "attribute":
                    return symbol.name, self.literal_value(symbol.value)
        if node.children:
            for child in node.children:
                return self.get_qual_name(child)

    def literal_value(self, node: Node) -> str:
        value = None
        nodetext = node.text.decode()

        match node.type:
            case "call":
                qual_call = self.get_qual_name(node)
                if qual_call is not None:
                    value = nodetext.replace(qual_call[0], qual_call[1], 1)
                else:
                    value = nodetext
            case "attribute":
                qual_attr = self.get_qual_name(node)
                if qual_attr is not None:
                    value = nodetext.replace(qual_attr[0], qual_attr[1], 1)
                else:
                    value = nodetext
            case "identifier":
                qual_ident = self.get_qual_name(node)
                if qual_ident is not None:
                    value = nodetext.replace(qual_ident[0], qual_ident[1], 1)
                else:
                    value = nodetext
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
                value = int(nodetext)
            case "float":
                value = float(nodetext)
            case "true":
                value = True
            case "false":
                value = False
        return value
