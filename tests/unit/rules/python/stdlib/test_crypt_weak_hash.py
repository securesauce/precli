# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class CryptWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY002"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("reversible_one_way_hash", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("328", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "crypt_crypt.py",
            "crypt_crypt_method_blowfish.py",
            "crypt_crypt_method_crypt.py",
            "crypt_crypt_method_md5.py",
            "crypt_crypt_method_sha256.py",
            "crypt_crypt_method_sha512.py",
            "crypt_mksalt.py",
            "crypt_mksalt_method_blowfish.py",
            "crypt_mksalt_method_crypt.py",
            "crypt_mksalt_method_md5.py",
            "crypt_mksalt_method_sha256.py",
            "crypt_mksalt_method_sha512.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
