# Copyright 2023 Secure Saurce LLC
from precli.parsers import base_parser


class Java(base_parser.Parser):

    def __init__(self):
        super().__init__("java")

    def file_extension(self):
        return ".java"

    def parse(self, data):
        tree = self.parser.parse(data)
