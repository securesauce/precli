# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class CryptWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY002"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "crypt",
            "examples",
        )

    def test_crypt_weak_hash_rule_meta(self):
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
            "crypt_crypt",
            "crypt_crypt_method_blowfish",
            "crypt_crypt_method_crypt",
            "crypt_crypt_method_md5",
            "crypt_crypt_method_sha256",
            "crypt_crypt_method_sha512",
            "crypt_mksalt",
            "crypt_mksalt_method_blowfish",
            "crypt_mksalt_method_crypt",
            "crypt_mksalt_method_md5",
            "crypt_mksalt_method_sha256",
            "crypt_mksalt_method_sha512",
        ]
    )
    def test(self, filename):
        self.check(filename)
