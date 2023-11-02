# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class CryptWeakHashTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE0002")
        self.assertEqual("PRE0002", rule.id)
        self.assertEqual("reversible_one_way_hash", rule.name)
        self.assertEqual(
            "https://docs.securesauce.dev/rules/PRE0002", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("328", rule.cwe.cwe_id)

    def test_crypt_crypt(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_crypt_method_blowfish(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt_method_blowfish.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_crypt_method_crypt(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt_method_crypt.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0002", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_crypt_crypt_method_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt_method_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0002", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_crypt_crypt_method_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt_method_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_crypt_method_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_crypt_method_sha512.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_mksalt(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_mksalt_method_blowfish(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt_method_blowfish.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_mksalt_method_crypt(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt_method_crypt.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0002", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(12, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_crypt_mksalt_method_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt_method_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0002", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(12, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_crypt_mksalt_method_sha256(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt_method_sha256.py")
        )
        self.assertEqual(0, len(results))

    def test_crypt_mksalt_method_sha512(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "crypt_mksalt_method_sha512.py")
        )
        self.assertEqual(0, len(results))
