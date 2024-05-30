# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestHttpUrlSecret(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY007"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "http",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "sensitive_query_strings"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 598

    @pytest.mark.parametrize(
        "filename",
        [
            "http_url_secret_apikey.py",
            "http_url_secret_apikey_in_header.py",
            "http_url_secret_basic_auth.py",
            "http_url_secret_basic_auth_as_var.py",
            "http_url_secret_password.py",
            "http_url_secret_username.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
