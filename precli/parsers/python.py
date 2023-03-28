# Copyright 2023 Secure Saurce LLC
from importlib.metadata import entry_points

from tree_sitter_languages import get_language
from tree_sitter_languages import get_parser


def traverse_tree(tree):
    cursor = tree.walk()

    reached_root = False
    while reached_root == False:
        yield cursor.node

        if cursor.goto_first_child():
            continue

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True

            if cursor.goto_next_sibling():
                retracing = False


class Python:
    def __init__(self):
        self.language = get_language("python")
        self.parser = get_parser("python")
        self.rules = {}

        discovered_rules = entry_points(group="precli.rules.python")
        for rule in discovered_rules:
            self.rules[rule.name] = rule.load()


    def file_extension(self):
        return ".py"

    def parse(self, data):
        tree = self.parser.parse(data)

        for node in traverse_tree(tree):
            if node.type == "call":
                print(node)
                for rule in self.rules.values():
                    rule()
