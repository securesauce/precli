# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class HashlibWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0004"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hashlib",
            "examples",
        )

    def test_hashlib_weak_hash_rule_meta(self):
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
            "hashlib_blake2b",
            "hashlib_blake2s",
            "hashlib_md4",
            "hashlib_md5",
            "hashlib_md5_usedforsecurity_true",
            "hashlib_new_blake2b",
            "hashlib_new_blake2s",
            "hashlib_new_md4",
            "hashlib_new_md5",
            "hashlib_new_md5_usedforsecurity_true",
            "hashlib_new_name_sha",
            "hashlib_new_ripemd160",
            "hashlib_new_sha",
            "hashlib_new_sha1",
            "hashlib_new_sha224",
            "hashlib_new_sha256",
            "hashlib_new_sha384",
            "hashlib_new_sha3_224",
            "hashlib_new_sha3_256",
            "hashlib_new_sha3_384",
            "hashlib_new_sha3_512",
            "hashlib_new_sha512",
            "hashlib_new_sha_usedforsecurity_false",
            "hashlib_new_shake_128",
            "hashlib_new_shake_256",
            "hashlib_pbkdf2_hmac_md4",
            "hashlib_pbkdf2_hmac_md5",
            "hashlib_pbkdf2_hmac_ripemd160",
            "hashlib_pbkdf2_hmac_sha",
            "hashlib_pbkdf2_hmac_sha1",
            "hashlib_pbkdf2_hmac_sha224",
            "hashlib_pbkdf2_hmac_sha256",
            "hashlib_pbkdf2_hmac_sha384",
            "hashlib_pbkdf2_hmac_sha3_224",
            "hashlib_pbkdf2_hmac_sha3_256",
            "hashlib_pbkdf2_hmac_sha3_384",
            "hashlib_pbkdf2_hmac_sha3_512",
            "hashlib_pbkdf2_hmac_shake_128",
            "hashlib_pbkdf2_hmac_shake_256",
            "hashlib_ripemd160",
            "hashlib_sha",
            "hashlib_sha1",
            "hashlib_sha224",
            "hashlib_sha256",
            "hashlib_sha384",
            "hashlib_sha3_224",
            "hashlib_sha3_256",
            "hashlib_sha3_384",
            "hashlib_sha3_512",
            "hashlib_sha512",
            "hashlib_sha_usedforsecurity_false",
            "hashlib_shake_128",
            "hashlib_shake_256",
        ]
    )
    def test(self, filename):
        self.check(filename)
