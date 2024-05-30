# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import java
from precli.rules import Rule
from tests.unit.rules import test_case


class TestWeakCipher(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "JAV001"
        cls.parser = java.Java()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "java",
            "stdlib",
            "javax_crypto",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "use_of_a_broken_or_risky_cryptographic_algorithm"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 327

    @pytest.mark.parametrize(
        "filename",
        [
            "Cipher3DESCBC.java",
            "CipherAESCBC.java",
            "CipherArcfour.java",
            "CipherBlowfishCBC.java",
            "CipherDESCBC.java",
            "CipherRC2.java",
            "CipherRC4.java",
            "CipherRC5.java",
        ],
    )
    def test(self, filename):
        self.check(filename)
