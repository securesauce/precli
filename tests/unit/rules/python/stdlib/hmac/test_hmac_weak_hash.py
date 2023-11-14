# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class HmacWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0006"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hmac",
            "examples",
        )

    def test_hmac_weak_hash_rule_meta(self):
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
            "hmac_digest_blake2b",
            "hmac_digest_blake2s",
            "hmac_digest_hashlib_blake2b",
            "hmac_digest_hashlib_blake2s",
            "hmac_digest_hashlib_md4",
            "hmac_digest_hashlib_md5",
            "hmac_digest_hashlib_ripemd160",
            "hmac_digest_hashlib_sha",
            "hmac_digest_hashlib_sha1",
            "hmac_digest_hashlib_sha224",
            "hmac_digest_hashlib_sha256",
            "hmac_digest_hashlib_sha384",
            "hmac_digest_hashlib_sha3_224",
            "hmac_digest_hashlib_sha3_256",
            "hmac_digest_hashlib_sha3_384",
            "hmac_digest_hashlib_sha3_512",
            "hmac_digest_hashlib_sha512",
            "hmac_digest_hashlib_shake_128",
            "hmac_digest_hashlib_shake_256",
            "hmac_digest_md4",
            "hmac_digest_md5",
            "hmac_digest_ripemd160",
            "hmac_digest_sha",
            "hmac_digest_sha1",
            "hmac_digest_sha224",
            "hmac_digest_sha256",
            "hmac_digest_sha384",
            "hmac_digest_sha3_224",
            "hmac_digest_sha3_256",
            "hmac_digest_sha3_384",
            "hmac_digest_sha3_512",
            "hmac_digest_sha512",
            "hmac_digest_shake_128",
            "hmac_digest_shake_256",
            "hmac_new_digestmod_blake2b",
            "hmac_new_digestmod_blake2s",
            "hmac_new_digestmod_hashlib_blake2b",
            "hmac_new_digestmod_hashlib_blake2s",
            "hmac_new_digestmod_hashlib_md4",
            "hmac_new_digestmod_hashlib_md5",
            "hmac_new_digestmod_hashlib_ripemd160",
            "hmac_new_digestmod_hashlib_sha",
            "hmac_new_digestmod_hashlib_sha1",
            "hmac_new_digestmod_hashlib_sha224",
            "hmac_new_digestmod_hashlib_sha256",
            "hmac_new_digestmod_hashlib_sha384",
            "hmac_new_digestmod_hashlib_sha3_224",
            "hmac_new_digestmod_hashlib_sha3_256",
            "hmac_new_digestmod_hashlib_sha3_384",
            "hmac_new_digestmod_hashlib_sha3_512",
            "hmac_new_digestmod_hashlib_sha512",
            "hmac_new_digestmod_hashlib_shake_128",
            "hmac_new_digestmod_hashlib_shake_256",
            "hmac_new_digestmod_md4",
            "hmac_new_digestmod_md5",
            "hmac_new_digestmod_ripemd160",
            "hmac_new_digestmod_sha",
            "hmac_new_digestmod_sha1",
            "hmac_new_digestmod_sha224",
            "hmac_new_digestmod_sha256",
            "hmac_new_digestmod_sha384",
            "hmac_new_digestmod_sha3_224",
            "hmac_new_digestmod_sha3_256",
            "hmac_new_digestmod_sha3_384",
            "hmac_new_digestmod_sha3_512",
            "hmac_new_digestmod_sha512",
            "hmac_new_digestmod_shake_128",
            "hmac_new_digestmod_shake_256",
        ]
    )
    def test(self, filename):
        self.check(filename)
