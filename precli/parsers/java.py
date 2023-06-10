# Copyright 2023 Secure Saurce LLC
from precli.core.parser import Parser


class Java(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("java", enabled, disabled)

    def file_extension(self) -> str:
        return ".java"
