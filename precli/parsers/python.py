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

    def child_by_type(self, node: Node, type: str) -> Node:
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.children))
        return child[0] if child else None

    def import_statement(self, nodes: list[Node]) -> dict:
        imports = dict()
        for child in nodes:
            if child.type == "dotted_name":
                imports[child.text] = child.text
            elif child.type == "aliased_import":
                module = self.child_by_type(child, "dotted_name")
                alias = self.child_by_type(child, "identifier")
                imports[alias.text] = module.text
        return imports

    def import_from_statement(self, nodes: list[Node]) -> dict:
        imports = dict()

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

    def get_call_arg(self, context: dict, node: Node) -> str:
        match node.type:
            case "attribute":
                attribute = node
                name = attribute.text
                if b"." in name:
                    name = name.rpartition(b".")[0]
                if name in context["imports"]:
                    qual_name = context["imports"][name]
                    return attribute.text.replace(name, qual_name)
                # TODO: else return attr text?
            case "identifier":
                name = node.text
                if name in context["imports"]:
                    return context["imports"][name]
                else:
                    return name
            case "dictionary":
                # TODO: need to avoid use of decode
                return ast.literal_eval(node.text.decode())
            case "list":
                # TODO: need to avoid use of decode
                return ast.literal_eval(node.text.decode())
            case "tuple":
                # TODO: need to avoid use of decode
                return ast.literal_eval(node.text.decode())
            case "string":
                # TODO: bytes and f-type strings are messed up
                return node.text
            case "integer":
                # TODO: hex, octal, binary
                return int(node.text)
            case "float":
                return float(node.text)
            case "true":
                return True
            case "false":
                return False
            case "none":
                return None
            case _:
                # TODO: complex
                print(node.type)
                print(node.text)

    def get_call_kwarg(self, context: dict, node: Node) -> dict:
        kwarg = dict()
        keyword = node.children[0].text
        kwarg[keyword] = self.get_call_arg(context, node.children[2])
        return kwarg

    def call(self, context: dict, nodes: list[Node]) -> tuple:
        # Resolve the fully qualified function name
        func_call_qual = ""
        first_node = next(nodes)
        func_call_qual = self.get_call_arg(context, first_node)

        # Get the arguments of the function call
        func_call_args = list()
        func_call_kwargs = dict()
        second_node = next(nodes)
        if second_node.type == "argument_list":
            for child in second_node.children:
                if child.type not in "(,)":
                    if child.type == "keyword_argument":
                        kwarg = self.get_call_kwarg(context, child)
                        func_call_kwargs = func_call_kwargs | kwarg
                    else:
                        arg = self.get_call_arg(context, child)
                        func_call_args.append(arg)

        return (func_call_qual, func_call_args, func_call_kwargs)

    def parse(self, data: bytes) -> list[Result]:
        results = list()
        context = dict()
        context["imports"] = dict()
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
