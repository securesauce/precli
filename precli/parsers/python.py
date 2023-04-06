# Copyright 2023 Secure Saurce LLC
from precli.core.parser import Parser
from precli.core.result import Result


class Python(Parser):
    def __init__(self):
        super().__init__("python")

    def file_extension(self):
        return ".py"

    def child_by_type(self, node, type):
        # Return first child with type as specified
        child = list(filter(lambda x: x.type == type, node.children))
        return child[0] if child else None

    def import_statement(self, nodes):
        imports = dict()
        for child in nodes:
            if child.type == "dotted_name":
                imports[child.text] = child.text
            elif child.type == "aliased_import":
                module = self.child_by_type(child, "dotted_name")
                alias = self.child_by_type(child, "identifier")
                imports[alias.text] = module.text
        return imports

    def import_from_statement(self, nodes):
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

    def call(self, nodes):
        first_node = next(nodes)
        if first_node.type == "attribute":
            attribute = first_node

        arguments = []
        second_node = next(nodes)
        if second_node.type == "argument_list":
            for child in second_node.children:
                if child.type not in "(,)":
                    arguments.append(child)

        # print(attribute)
        # print(arguments) 

    def parse(self, data) -> list[Result]:
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
                    self.call(iter(node.children))

            for rule in self.rules.values():
                result = rule.analyze(context)
                if result:
                    results.append(result)

        return results
