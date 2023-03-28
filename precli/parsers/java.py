# Copyright 2023 Secure Saurce LLC

from tree_sitter_languages import get_language
from tree_sitter_languages import get_parser


class Java:
    def __init__(self):
        self.language = get_language("java")
        self.parser = get_parser("java")

    def file_extension(self):
        return ".java"

    def parser(self):
        return self.parser
