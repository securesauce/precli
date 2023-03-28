# Copyright 2023 Secure Saurce LLC
import tree_sitter_languages


class Java:
    def __init__(self):
        self.language = tree_sitter_languages.get_language("java")
        self.parser = tree_sitter_languages.get_parser("java")
        self.rules = {}

    def file_extension(self):
        return ".java"

    def parse(self, data):
        tree = self.parser.parse(data)
