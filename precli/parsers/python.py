# Copyright 2023 Secure Saurce LLC
from precli.parsers import base_parser


class Python(base_parser.Parser):

    def __init__(self):
        super().__init__("python")

    def file_extension(self):
        return ".py"

    def parse(self, data):
        tree = self.parser.parse(data)

        for node in self.traverse_tree(tree):
            if node.type == "call":
                print(node)
                for rule in self.rules.values():
                    rule()
