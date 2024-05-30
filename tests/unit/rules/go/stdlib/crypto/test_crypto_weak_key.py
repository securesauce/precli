# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import go
from precli.rules import Rule
from tests.unit.rules import test_case


class TestCryptoWeakKey(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "GO003"
        cls.parser = go.Go()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "go",
            "stdlib",
            "crypto",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "inadequate_encryption_strength"
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
            "crypto_weak_key_dsa_1024.go",
            "crypto_weak_key_dsa_2048.go",
            "crypto_weak_key_dsa_3072.go",
            "crypto_weak_key_rsa_1024.go",
            "crypto_weak_key_rsa_2048.go",
            "crypto_weak_key_rsa_4096.go",
            "crypto_weak_key_rsa_bits_as_var.go",
        ],
    )
    def test(self, filename):
        self.check(filename)
