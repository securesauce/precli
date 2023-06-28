# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.core.rule import Rule
from precli.parsers import python
from tests.unit.rules.python import test_case


class HostKeyPolicyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python(enabled=["PRE0020"])
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
        rule = Rule.get_by_id("PRE0020")
        self.assertEqual("PRE0020", rule.id)
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
        self.assertEqual("PRE0020", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(46, result.location.start_column)
        self.assertEqual(59, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_host_key_auto_add_policy_kwarg(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "host_key_auto_add_policy_kwarg.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0020", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(53, result.location.start_column)
        self.assertEqual(66, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
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
        self.assertEqual("PRE0020", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(54, result.location.start_column)
        self.assertEqual(67, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_host_key_auto_add_policy_walrus(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "host_key_auto_add_policy_walrus.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0020", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(50, result.location.start_column)
        self.assertEqual(63, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_host_key_warning_policy_single_statement(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "host_key_warning_policy_single_statement.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0020", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(54, result.location.start_column)
        self.assertEqual(67, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
