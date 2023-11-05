# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class CryptographyWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python(enabled=["PRE0502"])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "cryptography",
            "examples",
        )

    def test_cryptography_weak_key_rule_meta(self):
        rule = Rule.get_by_id("PRE0502")
        self.assertEqual("PRE0502", rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual(
            "https://docs.securesauce.dev/rules/PRE0502", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    def test_dsa_generate_parameters_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(24, result.location.start_column)
        self.assertEqual(28, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_parameters_2048(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_2048.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_4096(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_4096.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_kwarg_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(37, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_parameters_kwarg_2048(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_2048.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_kwarg_4096(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_4096.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_var_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_var_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(24, result.location.start_column)
        self.assertEqual(31, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(25, result.location.start_column)
        self.assertEqual(29, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_2048(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_2048.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_4096(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_4096.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_kwarg_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(34, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_kwarg_2048(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_2048.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_kwarg_4096(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_4096.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_var_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_var_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(25, result.location.start_column)
        self.assertEqual(32, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
