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

    def get_call_arg(self, context: dict, node: Node) -> str:
        call_arg = None
        match node.type:
            case "attribute":
                attribute = node
                name = attribute.text
                if b"." in name:
                    name = name.rpartition(b".")[0]
                if name in context["imports"]:
                    qual_name = context["imports"][name]
                    call_arg = attribute.text.replace(name, qual_name)
                # TODO: else return attr text?
            case "identifier":
                name = node.text
                if name in context["imports"]:
                    call_arg = context["imports"][name]
                else:
                    call_arg = name
            case "dictionary":
                # TODO: need to avoid use of decode
                call_arg = ast.literal_eval(node.text.decode())
            case "list":
                # TODO: need to avoid use of decode
                call_arg = ast.literal_eval(node.text.decode())
            case "tuple":
                # TODO: need to avoid use of decode
                call_arg = ast.literal_eval(node.text.decode())
            case "string":
                # TODO: bytes and f-type strings are messed up
                call_arg = node.text
            case "integer":
                # TODO: hex, octal, binary
                call_arg = int(node.text)
            case "float":
                call_arg = float(node.text)
            case "true":
                call_arg = True
            case "false":
                call_arg = False

        return call_arg

    def get_call_kwarg(self, context: dict, node: Node) -> dict:
        kwarg = {}
        keyword = node.children[0].text
        kwarg[keyword] = self.get_call_arg(context, node.children[2])
        return kwarg

    def call(self, context: dict, nodes: list[Node]) -> tuple:
        # Resolve the fully qualified function name
        func_call_qual = ""
        first_node = next(nodes)
        func_call_qual = self.get_call_arg(context, first_node)

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
                        arg = self.get_call_arg(context, child)
                        func_call_args.append(arg)

        return (func_call_qual, func_call_args, func_call_kwargs)

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
