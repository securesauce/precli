# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class SslCreateContextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "ssl",
            "examples",
        )

    def test_unverified_context_rule_meta(self):
        rule = Rule.get_by_id("PRE0016")
        self.assertEqual("PRE0016", rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    def test_create_unverified_context(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "create_unverified_context.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0016", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(10, result.location.start_column)
        self.assertEqual(40, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_create_default_context(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "create_default_context.py")
        )
        self.assertEqual(0, len(results))
