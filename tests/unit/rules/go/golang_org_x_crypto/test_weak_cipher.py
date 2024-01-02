# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import go
from precli.rules import Rule
from tests.unit.rules import test_case


class CryptoWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "GO502"
        self.parser = go.Go(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "go",
            "golang_org_x_crypto",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual(
            "use_of_a_broken_or_risky_cryptographic_algorithm", rule.name
        )
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("327", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "weak_cipher_blowfish.go",
            "weak_cipher_blowfish_new_salted_cipher.go",
            "weak_cipher_cast5.go",
            "weak_cipher_tea.go",
            "weak_cipher_tea_new_cipher_with_rounds.go",
            "weak_cipher_twofish.go",
            "weak_cipher_xtea.go",
        ]
    )
    def test(self, filename):
        self.check(filename)
