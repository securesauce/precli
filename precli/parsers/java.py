# Copyright 2023 Secure Saurce LLC
from precli.core.parser import Parser
from precli.core.result import Result


class Java(Parser):
    def __init__(self):
        super().__init__("java")

    def file_extension(self) -> str:
        return ".java"

    def parse(self, data: bytes) -> list[Result]:
        tree = self.parser.parse(data)
