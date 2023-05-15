# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class WrapSocketTests(test_case.TestCase):
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

    def test_ssl_context_rule_meta(self):
        rule = Rule.get_by_id("PRE012")
        self.assertEqual("PRE012", rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    def test_ssl_context_sslv2(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_sslv2.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE012", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ssl_context_sslv23(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_sslv23.py")
        )
        self.assertEqual(0, len(results))

    def test_ssl_context_sslv3(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_sslv3.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE012", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ssl_context_tlsv1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_tlsv1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE012", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ssl_context_tlsv11(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_tlsv11.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE012", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(45, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ssl_context_tlsv12(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ssl_context_tlsv12.py")
        )
        self.assertEqual(0, len(results))
