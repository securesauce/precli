# Copyright 2024 Secure Saurce LLC
from precli.parsers import Parser


class Java(Parser):
    def __init__(self, enabled: list = None, disabled: list = None):
        super().__init__("java", enabled, disabled)
