# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class HmacWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE0005")
        self.assertEqual("PRE0005", rule.id)
        self.assertEqual("reversible_one_way_hash", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("328", rule.cwe.cwe_id)

    def test_hmac_digest_blake2b(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_blake2b.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_blake2s(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_blake2s.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_blake2b(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_blake2b.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_blake2s(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_blake2s.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_hashlib_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_hashlib_ripemd160(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_ripemd160.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(50, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_hashlib_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_hashlib_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(45, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_hashlib_sha224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha224.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha3_224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha3_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha3_384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha3_512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_shake_128(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_shake_128.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_hashlib_shake_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_hashlib_shake_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_ripemd160(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_ripemd160.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(39, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_digest_sha224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha224.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha3_224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha3_224.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha3_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha3_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha3_384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha3_384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha3_512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha3_512.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_shake_128(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_shake_128.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_digest_shake_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_digest_shake_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_blake2b(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_blake2b.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_blake2s(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_blake2s.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_blake2b(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_blake2b.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_blake2s(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_blake2s.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_hashlib_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_hashlib_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_hashlib_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_hashlib_ripemd160(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_ripemd160.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(54, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_hashlib_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_hashlib_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_hashlib_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_hashlib_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(49, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_hashlib_sha224(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha224.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha256(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha256.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha384(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha384.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha3_224(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha3_224.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha3_256(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha3_256.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha3_384(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha3_384.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha3_512(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha3_512.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_sha512(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_sha512.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_shake_128(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_shake_128.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_hashlib_shake_256(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_new_digestmod_hashlib_shake_256.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_ripemd160(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_ripemd160.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_new_digestmod_sha224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha224.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha3_224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha3_224.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha3_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha3_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha3_384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha3_384.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha3_512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha3_512.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_shake_128(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_shake_128.py")
        )
        self.assertEqual(0, len(results))

    def test_hmac_new_digestmod_shake_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_new_digestmod_shake_256.py")
        )
        self.assertEqual(0, len(results))
