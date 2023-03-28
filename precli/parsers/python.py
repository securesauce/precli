# Copyright 2023 Secure Saurce LLC
from importlib.metadata import entry_points

import tree_sitter_languages


def traverse_tree(tree):
    cursor = tree.walk()

    reached_root = False
    while reached_root is False:
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
        self.language = tree_sitter_languages.get_language("python")
        self.parser = tree_sitter_languages.get_parser("python")
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
