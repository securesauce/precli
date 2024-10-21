# Copyright 2023 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
from precli.parsers import python


class TestPython:
    @classmethod
    def setup_class(cls):
        cls.parser = python.Python(skip_tests=False)
