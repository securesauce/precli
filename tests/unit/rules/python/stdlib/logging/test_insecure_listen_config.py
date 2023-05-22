# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class InsecureListenConfigTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "logging",
            "examples",
        )

    def test_insecure_listen_config_rule_meta(self):
        rule = Rule.get_by_id("PRE007")
        self.assertEqual("PRE007", rule.id)
        self.assertEqual("code_injection", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("94", rule.cwe.cwe_id)

    def test_insecure_listen_config_empty_args(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_empty_args.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_port_verify_as_var(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_port_verify_as_var.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_port_verify_none(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_port_verify_none.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_port(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "insecure_listen_config_port.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_verify_none_port(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_verify_none_port.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_verify_none(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_verify_none.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_insecure_listen_config_verify_set(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "insecure_listen_config_verify_set.py"
            )
        )
        self.assertEqual(0, len(results))
