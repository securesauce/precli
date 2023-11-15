# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class PycryptoWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0513"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "pycrypto",
            "examples",
        )

    def test_pycrypto_weak_key_rule_meta(self):
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
            "dsa_generate_1024",
            "dsa_generate_2048",
            "dsa_generate_4096",
            "rsa_generate_1024",
            "rsa_generate_2048",
            "rsa_generate_4096",
        ]
    )
    def test(self, filename):
        self.check(filename)