# Copyright 2023 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestCryptWeakHash(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY002"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "crypt",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "reversible_one_way_hash"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.cwe_id == "328"

    @pytest.mark.parametrize(
        "filename",
        [
            "crypt_crypt.py",
            "crypt_crypt_method_blowfish.py",
            "crypt_crypt_method_crypt.py",
            "crypt_crypt_method_md5.py",
            "crypt_crypt_method_sha256.py",
            "crypt_crypt_method_sha512.py",
            "crypt_mksalt.py",
            "crypt_mksalt_method_blowfish.py",
            "crypt_mksalt_method_crypt.py",
            "crypt_mksalt_method_md5.py",
            "crypt_mksalt_method_sha256.py",
            "crypt_mksalt_method_sha512.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
