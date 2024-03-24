# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class HmacWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY034"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hmac",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("insufficient_key_size", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "hmac_digest_weak_key_hashlib_blake2b.py",
            "hmac_digest_weak_key_hashlib_sha3_256.py",
            "hmac_digest_weak_key_hashlib_sm3.py",
            "hmac_digest_weak_key_sha224.py",
            "hmac_digest_weak_key_sha256.py",
            "hmac_digest_weak_key_sha512.py",
            "hmac_new_weak_key_blake2s.py",
            "hmac_new_weak_key_hashlib_sha3_224.py",
            "hmac_new_weak_key_hashlib_sha3_384.py",
            "hmac_new_weak_key_hashlib_sha3_512.py",
            "hmac_new_weak_key_sha384.py",
            "hmac_new_weak_key_sha512_256.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
