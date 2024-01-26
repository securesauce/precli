# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class HashlibWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY004"
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
            "hashlib_blake2b.py",
            "hashlib_blake2s.py",
            "hashlib_md4.py",
            "hashlib_md5.py",
            "hashlib_md5_usedforsecurity_true.py",
            "hashlib_new_blake2b.py",
            "hashlib_new_blake2s.py",
            "hashlib_new_md4.py",
            "hashlib_new_md5.py",
            "hashlib_new_md5_usedforsecurity_true.py",
            "hashlib_new_name_sha.py",
            "hashlib_new_ripemd160.py",
            "hashlib_new_sha.py",
            "hashlib_new_sha1.py",
            "hashlib_new_sha224.py",
            "hashlib_new_sha256.py",
            "hashlib_new_sha384.py",
            "hashlib_new_sha3_224.py",
            "hashlib_new_sha3_256.py",
            "hashlib_new_sha3_384.py",
            "hashlib_new_sha3_512.py",
            "hashlib_new_sha512.py",
            "hashlib_new_sha_usedforsecurity_false.py",
            "hashlib_new_shake_128.py",
            "hashlib_new_shake_256.py",
            "hashlib_pbkdf2_hmac_md4.py",
            "hashlib_pbkdf2_hmac_md5.py",
            "hashlib_pbkdf2_hmac_ripemd160.py",
            "hashlib_pbkdf2_hmac_sha.py",
            "hashlib_pbkdf2_hmac_sha1.py",
            "hashlib_pbkdf2_hmac_sha224.py",
            "hashlib_pbkdf2_hmac_sha256.py",
            "hashlib_pbkdf2_hmac_sha384.py",
            "hashlib_pbkdf2_hmac_sha3_224.py",
            "hashlib_pbkdf2_hmac_sha3_256.py",
            "hashlib_pbkdf2_hmac_sha3_384.py",
            "hashlib_pbkdf2_hmac_sha3_512.py",
            "hashlib_pbkdf2_hmac_shake_128.py",
            "hashlib_pbkdf2_hmac_shake_256.py",
            "hashlib_ripemd160.py",
            "hashlib_sha.py",
            "hashlib_sha1.py",
            "hashlib_sha224.py",
            "hashlib_sha256.py",
            "hashlib_sha384.py",
            "hashlib_sha3_224.py",
            "hashlib_sha3_256.py",
            "hashlib_sha3_384.py",
            "hashlib_sha3_512.py",
            "hashlib_sha512.py",
            "hashlib_sha_usedforsecurity_false.py",
            "hashlib_shake_128.py",
            "hashlib_shake_256.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
