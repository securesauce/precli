# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class TelnetlibCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "telnetlib",
            "examples",
        )

    def test_telnetlib_cleartext_rule_meta(self):
        rule = Rule.get_by_id("PRE0018")
        self.assertEqual("PRE0018", rule.id)
        self.assertEqual("cleartext_transmission", rule.name)
        self.assertEqual(
            "https://docs.securesauce.dev/rules/PRE0018", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("319", rule.cwe.cwe_id)

    def test_telnet(self):
        results = self.parser.parse(os.path.join(self.base_path, "telnet.py"))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0018", result.rule_id)
        self.assertEqual(9, result.location.start_line)
        self.assertEqual(9, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_telnetlib_telnet(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "telnetlib_telnet.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0018", result.rule_id)
        self.assertEqual(9, result.location.start_line)
        self.assertEqual(9, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(21, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_telnetlib_telnet_context_mgr(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "telnetlib_telnet_context_mgr.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0018", result.rule_id)
        self.assertEqual(9, result.location.start_line)
        self.assertEqual(9, result.location.end_line)
        self.assertEqual(5, result.location.start_column)
        self.assertEqual(21, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
