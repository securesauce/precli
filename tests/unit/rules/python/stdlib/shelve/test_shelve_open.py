# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class ShelveOpenTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "shelve",
            "examples",
        )

    def test_shelve_open_rule_meta(self):
        rule = Rule.get_by_id("PRE0014")
        self.assertEqual("PRE0014", rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    def test_shelve_dbfilenameshelf(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "shelve_dbfilenameshelf.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0014", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(27, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_shelve_open(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "shelve_open.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0014", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_shelve_open_context_mgr(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "shelve_open_context_mgr.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0014", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
