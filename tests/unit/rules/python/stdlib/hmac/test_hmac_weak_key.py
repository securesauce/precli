# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestHmacWeakKey(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY034"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
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
        assert rule.id == self.rule_id
        assert rule.name == "insufficient_key_size"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 326

    @pytest.mark.parametrize(
        "filename",
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
        ],
    )
    def test(self, filename):
        self.check(filename)
