# Copyright 2023 Secure Saurce LLC
import ast

from tree_sitter import Node

from precli.core.parser import Parser


class Python(Parser):
    def __init__(self):
        super().__init__("python")

    def file_extension(self) -> str:
        return ".py"

    def visit_module(self, nodes: list[Node]):
        self.symbol_table = [{"imports": {}}]
        self.visit(nodes)
        self.symbol_table.pop()

    def visit_import_statement(self, nodes: list[Node]):
        imps = self.import_statement(nodes)
        self.symbol_table[-1]["imports"].update(imps)

    def visit_import_from_statement(self, nodes: list[Node]):
        imps = self.import_from_statement(nodes)
        self.symbol_table[-1]["imports"].update(imps)

    def visit_class_definition(self, nodes: list[Node]):
        self.symbol_table.append({"imports": {}})
        self.visit(nodes)
        self.symbol_table.pop()

    def visit_function_definition(self, nodes: list[Node]):
        self.symbol_table.append({"imports": {}})
        self.visit(nodes)
        self.symbol_table.pop()

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
        first_node = nodes[0]
        func_call_qual = self.get_qual_name(first_node)
        if func_call_qual is not None:
            func_call_qual = first_node.text.decode().replace(
                func_call_qual[0], func_call_qual[1], 1
            )
        self.context["func_call_qual"] = func_call_qual

        # Get the arguments of the function call
        func_call_args = []
        func_call_kwargs = {}
        second_node = nodes[1]
        if second_node.type == "argument_list":
            for child in second_node.named_children:
                if child.type == "keyword_argument":
                    kwarg = self.get_call_kwarg(child)
                    func_call_kwargs = func_call_kwargs | kwarg
                else:
                    arg = self.literal_value(child)
                    func_call_args.append(arg)
        self.context["func_call_args"] = func_call_args
        self.context["func_call_kwargs"] = func_call_kwargs

    def get_qual_name(self, node: Node) -> tuple:
        nodetext = node.text.decode()

        for symtab in self.symbol_table[::-1]:
            if nodetext in symtab["imports"]:
                return nodetext, symtab["imports"].get(nodetext)
        if node.children:
            for child in node.children:
                return self.get_qual_name(child)

    def get_call_kwarg(self, node: Node) -> dict:
        kwarg = {}
        keyword = node.children[0].text.decode()
        kwarg[keyword] = self.literal_value(node.children[2])
        return kwarg

    def literal_value(self, node: Node) -> str:
        value = None
        nodetext = node.text.decode()
        match node.type:
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
