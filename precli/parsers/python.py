# Copyright 2023 Secure Saurce LLC
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

    def get_qual_value(self, context: dict, node: Node) -> str:
        if node.type == "attribute":
            attribute = node
            name = attribute.text
            if b"." in name:
                name = name.rpartition(b".")[0]

            if name in context["imports"]:
                return attribute.text.replace(name, context["imports"][name])
        elif node.type == "identifier":
            name = node.text
            if name in context["imports"]:
                return context["imports"][name]
        elif node.type == "keyword_argument":
            kwarg = {}
            keyword = node.children[0].text
            kwarg[keyword] = self.get_qual_value(context, node.children[2])
            return kwarg

    def call(self, context: dict, nodes: list[Node]):
        # Resolve the fully qualified function name
        func_call_qual = ""
        first_node = next(nodes)
        func_call_qual = self.get_qual_value(context, first_node)

        # Get the arguments of the function call
        func_call_args = []
        second_node = next(nodes)
        if second_node.type == "argument_list":
            for child in second_node.children:
                if child.type not in "(,)":
                    arg_value = self.get_qual_value(context, child)
                    func_call_args.append(arg_value)

        return (func_call_qual, func_call_args)

    def parse(self, data: bytes) -> list[Result]:
        results = []
        context = dict()
        context["imports"] = {}
        tree = self.parser.parse(data)

        for node in Parser.traverse_tree(tree):
            context["node"] = node
            match node.type:
                case "import_statement":
                    imps = self.import_statement(iter(node.children))
                    context["imports"].update(imps)

                case "import_from_statement":
                    imps = self.import_from_statement(iter(node.children))
                    context["imports"].update(imps)

                case "call":
                    (func, args) = self.call(context, iter(node.children))
                    context["func_call_qual"] = func
                    context["func_call_args"] = args

            for rule in self.rules.values():
                result = rule.analyze(context)
                if result:
                    results.append(result)

        return results
