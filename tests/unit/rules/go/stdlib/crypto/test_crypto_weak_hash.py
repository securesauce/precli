# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import go
from precli.rules import Rule
from tests.unit.rules import test_case


class TestCryptoWeakHash(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "GO002"
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
        assert rule.name == "reversible_one_way_hash"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 328

    @pytest.mark.parametrize(
        "filename",
        [
            "crypto_weak_hash_md5_new.go",
            "crypto_weak_hash_md5_sum.go",
            "crypto_weak_hash_sha1_new.go",
            "crypto_weak_hash_sha1_sum.go",
            "crypto_weak_hash_sha256_new.go",
            "crypto_weak_hash_sha256_sum.go",
        ],
    )
    def test(self, filename):
        self.check(filename)
