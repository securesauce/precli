# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestHashlibImproperPrng(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY035"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hashlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "improper_random"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 330

    @pytest.mark.parametrize(
        "filename",
        [
            "hashlib_improper_prng_blake2b.py",
            "hashlib_improper_prng_blake2s.py",
            "hashlib_improper_prng_pbkdf2_hmac.py",
            "hashlib_improper_prng_scrypt.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
