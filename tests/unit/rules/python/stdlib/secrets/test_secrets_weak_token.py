# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class SecretsWeakTokenTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY028"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "secrets",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("insufficient_token_length", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "secrets_token_bytes.py",
            "secrets_token_bytes_default.py",
            "secrets_token_hex.py",
            "secrets_token_urlsafe.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
