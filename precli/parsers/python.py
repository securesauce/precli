# Copyright 2023 Secure Saurce LLC
from precli.parsers import base_parser


class Python(base_parser.Parser):

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
            from_module = b""

        result = self.import_statement(nodes)
        for key, value in result.items():
            full_qual = [from_module, value]
            imports[key] = b".".join(filter(None, full_qual))

        return imports

    def parse(self, data):
        tree = self.parser.parse(data)

        imports = dict()

        for node in self.traverse_tree(tree):
            match node.type:
                case "import_statement":
                    imps = self.import_statement(iter(node.children))
                    imports.update(imps)

                case "import_from_statement":
                    imps = self.import_from_statement(iter(node.children))
                    imports.update(imps)

                case "call":
                    #print(node)
                    #print(node.text)
                    #print(node.start_point)
                    #print(node.end_point)
                    #for rule in self.rules.values():
                    #    rule()
                    pass

                case _:
                    #print("Unknown node type.")
                    pass

        print("")
        print(imports)
