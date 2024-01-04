# Copyright 2023 Secure Saurce LLC
import os

import testtools

from precli.core.level import Level
from precli.parsers import python


class TestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "parsers",
            "examples",
        )

    def test_suppress(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_lowercase_rule(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_lowercase_rule.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiline(self):
        # TODO: not testing multiline
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_multiline.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiple_comments(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_multiple_comments.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiple_rules(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_multiple_rules.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_preceding(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_preceding.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_spaced_rules(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_spaced_rules.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_wrong_rule(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "suppress_wrong_rule.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PY004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
