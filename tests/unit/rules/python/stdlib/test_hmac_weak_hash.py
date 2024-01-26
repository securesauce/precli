# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class HmacWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY006"
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
            "hmac_digest_blake2b.py",
            "hmac_digest_blake2s.py",
            "hmac_digest_hashlib_blake2b.py",
            "hmac_digest_hashlib_blake2s.py",
            "hmac_digest_hashlib_md4.py",
            "hmac_digest_hashlib_md5.py",
            "hmac_digest_hashlib_ripemd160.py",
            "hmac_digest_hashlib_sha.py",
            "hmac_digest_hashlib_sha1.py",
            "hmac_digest_hashlib_sha224.py",
            "hmac_digest_hashlib_sha256.py",
            "hmac_digest_hashlib_sha384.py",
            "hmac_digest_hashlib_sha3_224.py",
            "hmac_digest_hashlib_sha3_256.py",
            "hmac_digest_hashlib_sha3_384.py",
            "hmac_digest_hashlib_sha3_512.py",
            "hmac_digest_hashlib_sha512.py",
            "hmac_digest_hashlib_shake_128.py",
            "hmac_digest_hashlib_shake_256.py",
            "hmac_digest_md4.py",
            "hmac_digest_md5.py",
            "hmac_digest_ripemd160.py",
            "hmac_digest_sha.py",
            "hmac_digest_sha1.py",
            "hmac_digest_sha224.py",
            "hmac_digest_sha256.py",
            "hmac_digest_sha384.py",
            "hmac_digest_sha3_224.py",
            "hmac_digest_sha3_256.py",
            "hmac_digest_sha3_384.py",
            "hmac_digest_sha3_512.py",
            "hmac_digest_sha512.py",
            "hmac_digest_shake_128.py",
            "hmac_digest_shake_256.py",
            "hmac_new_digestmod_blake2b.py",
            "hmac_new_digestmod_blake2s.py",
            "hmac_new_digestmod_hashlib_blake2b.py",
            "hmac_new_digestmod_hashlib_blake2s.py",
            "hmac_new_digestmod_hashlib_md4.py",
            "hmac_new_digestmod_hashlib_md5.py",
            "hmac_new_digestmod_hashlib_ripemd160.py",
            "hmac_new_digestmod_hashlib_sha.py",
            "hmac_new_digestmod_hashlib_sha1.py",
            "hmac_new_digestmod_hashlib_sha224.py",
            "hmac_new_digestmod_hashlib_sha256.py",
            "hmac_new_digestmod_hashlib_sha384.py",
            "hmac_new_digestmod_hashlib_sha3_224.py",
            "hmac_new_digestmod_hashlib_sha3_256.py",
            "hmac_new_digestmod_hashlib_sha3_384.py",
            "hmac_new_digestmod_hashlib_sha3_512.py",
            "hmac_new_digestmod_hashlib_sha512.py",
            "hmac_new_digestmod_hashlib_shake_128.py",
            "hmac_new_digestmod_hashlib_shake_256.py",
            "hmac_new_digestmod_md4.py",
            "hmac_new_digestmod_md5.py",
            "hmac_new_digestmod_ripemd160.py",
            "hmac_new_digestmod_sha.py",
            "hmac_new_digestmod_sha1.py",
            "hmac_new_digestmod_sha224.py",
            "hmac_new_digestmod_sha256.py",
            "hmac_new_digestmod_sha384.py",
            "hmac_new_digestmod_sha3_224.py",
            "hmac_new_digestmod_sha3_256.py",
            "hmac_new_digestmod_sha3_384.py",
            "hmac_new_digestmod_sha3_512.py",
            "hmac_new_digestmod_sha512.py",
            "hmac_new_digestmod_shake_128.py",
            "hmac_new_digestmod_shake_256.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
