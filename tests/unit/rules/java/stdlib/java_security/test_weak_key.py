# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import java
from precli.rules import Rule
from tests.unit.rules import test_case


class TestKeyPairGeneratorWeakkey(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "JAV003"
        cls.parser = java.Java()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "java",
            "stdlib",
            "java_security",
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
            "KeyPairGeneratorDSA.java",
            "KeyPairGeneratorRSA.java",
        ],
    )
    def test(self, filename):
        self.check(filename)
