# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class HashlibWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE0004")
        self.assertEqual("PRE0004", rule.id)
        self.assertEqual("reversible_one_way_hash", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("328", rule.cwe.cwe_id)

    def test_hashlib_blake2b(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_blake2b.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_blake2s(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_blake2s.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_md5_usedforsecurity_true(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_md5_usedforsecurity_true.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_blake2b(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_blake2b.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_blake2s(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_blake2s.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_md4(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_md4.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_md5_usedforsecurity_true(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hashlib_new_md5_usedforsecurity_true.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_name_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_name_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_ripemd160(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_ripemd160.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_new_sha224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha224.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha3_224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha3_224.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha3_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha3_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha3_384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha3_384.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha3_512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha3_512.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_sha_usedforsecurity_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hashlib_new_sha_usedforsecurity_false.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_shake_128(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_shake_128.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_new_shake_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_new_shake_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_ripemd160(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_ripemd160.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(17, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_sha(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_sha1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0004", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(12, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hashlib_sha224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha224.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha384.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha3_224(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha3_224.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha3_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha3_256.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha3_384(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha3_384.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha3_512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha3_512.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_sha_usedforsecurity_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hashlib_sha_usedforsecurity_false.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_hashlib_shake_128(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_shake_128.py")
        )
        self.assertEqual(0, len(results))

    def test_hashlib_shake_256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hashlib_shake_256.py")
        )
        self.assertEqual(0, len(results))
