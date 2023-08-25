# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class MktempRaceConditionTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "tempfile",
            "examples",
        )

    def test_smtp_cleartext_rule_meta(self):
        rule = Rule.get_by_id("PRE0019")
        self.assertEqual("PRE0019", rule.id)
        self.assertEqual("insecure_temporary_file", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("377", rule.cwe.cwe_id)

    def test_tempfile_mktemp(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "tempfile_mktemp.py")
        )
        self.assertEqual(0, len(results))

    def test_tempfile_mktemp_args_open(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "tempfile_mktemp_args_open.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0019", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(4, result.location.start_column)
        self.assertEqual(8, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_tempfile_mktemp_args_with_open_args(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "tempfile_mktemp_args_with_open_args.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0019", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_tempfile_mktemp_open(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "tempfile_mktemp_open.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0019", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(4, result.location.start_column)
        self.assertEqual(8, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_tempfile_mktemp_with_open(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "tempfile_mktemp_with_open.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0019", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_tempfile_mktemp_with_open_multiline(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "tempfile_mktemp_with_open_multiline.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0019", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
