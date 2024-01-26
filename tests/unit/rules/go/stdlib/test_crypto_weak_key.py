# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import go
from precli.rules import Rule
from tests.unit.rules import test_case


class CryptoWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "GO003"
        self.parser = go.Go()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "go",
            "stdlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "crypto_weak_key_dsa_1024.go",
            "crypto_weak_key_dsa_2048.go",
            "crypto_weak_key_dsa_3072.go",
            "crypto_weak_key_rsa_1024.go",
            "crypto_weak_key_rsa_2048.go",
            "crypto_weak_key_rsa_4096.go",
            "crypto_weak_key_rsa_bits_as_var.go",
        ]
    )
    def test(self, filename):
        self.check(filename)
