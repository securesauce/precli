# Copyright 2023 Secure Saurce LLC
from precli.core.parser import Parser


class Java(Parser):
    def __init__(self):
        super().__init__("java")

    def file_extension(self) -> str:
        return ".java"
