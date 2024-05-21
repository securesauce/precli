# Copyright 2023 Secure Sauce LLC
from precli.parsers import python


class TestPython:
    @classmethod
    def setup_class(cls):
        cls.parser = python.Python()
