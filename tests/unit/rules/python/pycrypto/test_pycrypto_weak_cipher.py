# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class PycryptoWeakCipherTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY513"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "pycrypto",
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
            "cipher_arc2.py",
            "cipher_arc4.py",
            "cipher_blowfish.py",
            "cipher_des.py",
            "cipher_xor.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
