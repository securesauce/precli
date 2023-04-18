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
        results = []
        context = {}
        context["file_name"] = file_name
        context["imports"] = {}
        tree = self.parser.parse(data)

        for node in Parser.traverse_tree(tree):
            context["node"] = node
            match node.type:
                case "import_statement":
                    children = iter(node.children)
                    imps = self.import_statement(children)
                    context["imports"].update(imps)
                case "import_from_statement":
                    children = iter(node.children)
                    imps = self.import_from_statement(children)
                    context["imports"].update(imps)
                case "call":
                    children = iter(node.children)
                    (func, args, kwargs) = self.call(context, children)
                    context["func_call_qual"] = func
                    context["func_call_args"] = args
                    context["func_call_kwargs"] = kwargs

            for rule in self.rules.values():
                result = rule.analyze(context)
                if result:
                    results.append(result)

        return results

    def child_by_type(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.children))
        return child[0] if child else None

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = {}
        for child in nodes:
            if child.type == "dotted_name":
                imports[child.text] = child.text
            elif child.type == "aliased_import":
                module = self.child_by_type(child, "dotted_name")
                alias = self.child_by_type(child, "identifier")
                imports[alias.text] = module.text
        return imports

    def import_from_statement(self, nodes: list[Node]) -> dict:
        imports = {}

        # Skip over the "from" node
        next(nodes)

        module = next(nodes)
        if module.type == "dotted_name":
            from_module = module.text
        elif module.type == "relative_import":
            # No known way to resolve the relative to absolute
            # However, shouldn't matter much since most rules
            # won't check for local modules.
            from_module = b""

        result = self.import_statement(nodes)
        for key, value in result.items():
            full_qual = [from_module, value]
            imports[key] = b".".join(filter(None, full_qual))

        return imports

    def literal_value(self, context: dict, node: Node) -> str:
        value = None
        match node.type:
            case "attribute":
                qual_attr = self.get_qual_name(context, node)
                if qual_attr is not None:
                    value = node.text.replace(qual_attr[0], qual_attr[1], 1)
                else:
                    value = node.text
            case "identifier":
                value = context["imports"].get(node.text, node.text)
            case "dictionary":
                # TODO: need to avoid use of decode
                value = ast.literal_eval(node.text.decode())
            case "list":
                # TODO: need to avoid use of decode
                value = ast.literal_eval(node.text.decode())
            case "tuple":
                # TODO: need to avoid use of decode
                value = ast.literal_eval(node.text.decode())
            case "string":
                # TODO: bytes and f-type strings are messed up
                value = node.text
            case "integer":
                # TODO: hex, octal, binary
                value = int(node.text)
            case "float":
                value = float(node.text)
            case "true":
                value = True
            case "false":
                value = False
        return value

    def get_call_kwarg(self, context: dict, node: Node) -> dict:
        kwarg = {}
        keyword = node.children[0].text
        kwarg[keyword] = self.literal_value(context, node.children[2])
        return kwarg

    def get_qual_name(self, context: dict, node: Node) -> str:
        if node.text in context["imports"]:
            return node.text, context["imports"].get(node.text)
        elif node.children:
            for child in node.children:
                return self.get_qual_name(context, child)

    def call(self, context: dict, nodes: list[Node]) -> tuple:
        # Resolve the fully qualified function name
        first_node = next(nodes)
        func_call_qual = self.get_qual_name(context, first_node)
        if func_call_qual is not None:
            func_call_qual = first_node.text.replace(
                func_call_qual[0], func_call_qual[1], 1
            ).decode()

        # Get the arguments of the function call
        func_call_args = []
        func_call_kwargs = {}
        second_node = next(nodes)
        if second_node.type == "argument_list":
            for child in second_node.children:
                if child.type not in "(,)":
                    if child.type == "keyword_argument":
                        kwarg = self.get_call_kwarg(context, child)
                        func_call_kwargs = func_call_kwargs | kwarg
                    else:
                        arg = self.literal_value(context, child)
                        func_call_args.append(arg)

        return (func_call_qual, func_call_args, func_call_kwargs)
