# Copyright 2023 Secure Saurce LLC
import ast

from tree_sitter import Node

from precli.core.parser import Parser
from precli.core.result import Result


class Python(Parser):
    def __init__(self):
        super().__init__("python")

    def file_extension(self) -> str:
        return ".py"

    def parse(self, file_name: str, data: bytes) -> list[Result]:
        self.results = []
        self.context = {"file_name": file_name}
        tree = self.parser.parse(data)
        self.visit([tree.root_node])
        return self.results

    def visit(self, nodes: list[Node]):
        for node in nodes:
            self.context["node"] = node

            match node.type:
                case "module":
                    self.symbol_table = [{"imports": {}}]
                    self.visit(node.children)
                    self.symbol_table.pop()
                case "import_statement":
                    imps = self.import_statement(node.children)
                    self.symbol_table[-1]["imports"].update(imps)
                case "import_from_statement":
                    imps = self.import_from_statement(node.children)
                    self.symbol_table[-1]["imports"].update(imps)
                case "class_definition":
                    self.symbol_table.append({"imports": {}})
                    self.visit(node.children)
                    self.symbol_table.pop()
                case "function_definition":
                    self.symbol_table.append({"imports": {}})
                    self.visit(node.children)
                    self.symbol_table.pop()
                case "call":
                    self.call(node.children)
                    self.results += self.exec_rule("call")
                    self.context["func_call_qual"] = None
                    self.context["func_call_args"] = None
                    self.context["func_call_kwargs"] = None
                case _:
                    self.visit(node.children)

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

        result = self.import_statement(nodes[2:])
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
                # TODO: need to avoid use of decode
                value = ast.literal_eval(nodetext)
            case "list":
                # TODO: need to avoid use of decode
                value = ast.literal_eval(nodetext)
            case "tuple":
                # TODO: need to avoid use of decode
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

    def exec_rule(self, target: str) -> list[Result]:
        results = []
        for rule in self.rules.values():
            if target in rule.targets:
                result = rule.analyze(self.context)
                if result:
                    results.append(result)
        return results
