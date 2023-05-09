# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class HostKeyPolicyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "paramiko",
            "examples",
        )

    def test_paramiko_no_host_key_verify_rule_meta(self):
        rule = Rule.get_by_id("PRE305")
        self.assertEqual("PRE305", rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    def test_host_key_auto_add_policy(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "host_key_auto_add_policy.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE305", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(60, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_host_key_auto_add_policy_in_func(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "host_key_auto_add_policy_in_func.py")
        )
        # TODO(ericwb): false negative
        self.assertEqual(0, len(results))

    def test_host_key_auto_add_policy_single_statement(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "host_key_auto_add_policy_single_statement.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE305", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(68, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_host_key_warning_policy_single_statement(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "host_key_warning_policy_single_statement.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE305", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(68, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)