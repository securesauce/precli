# Copyright 2023 Secure Saurce LLC
import testtools

from precli.parsers import python


class PythonTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python()
