# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class PopCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "poplib",
            "examples",
        )

    def test_pop_cleartext_rule_meta(self):
        rule = Rule.get_by_id("PRE0013")
        self.assertEqual("PRE0013", rule.id)
        self.assertEqual("cleartext_transmission", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("319", rule.cwe.cwe_id)

    def test_poplib_pop3_apop(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_apop.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0013", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(2, result.location.start_column)
        self.assertEqual(6, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_poplib_pop3_context_mgr(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_context_mgr.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0013", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(13, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_poplib_pop3_pass_(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_pass_.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0013", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(2, result.location.start_column)
        self.assertEqual(7, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_poplib_pop3_rpop(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_rpop.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0013", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(2, result.location.start_column)
        self.assertEqual(6, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_poplib_pop3_ssl(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_ssl.py")
        )
        self.assertEqual(0, len(results))

    def test_poplib_pop3_stls(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_stls.py")
        )
        self.assertEqual(0, len(results))

    def test_poplib_pop3_user(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "poplib_pop3_user.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0013", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(2, result.location.start_column)
        self.assertEqual(6, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
