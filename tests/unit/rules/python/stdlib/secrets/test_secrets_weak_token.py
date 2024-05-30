# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestSecretsWeakToken(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY028"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "secrets",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "insufficient_token_length"
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
            "secrets_token_bytes.py",
            "secrets_token_bytes_default.py",
            "secrets_token_bytes_size_var.py",
            "secrets_token_hex.py",
            "secrets_token_hex_nbytes_unknown.py",
            "secrets_token_urlsafe.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
