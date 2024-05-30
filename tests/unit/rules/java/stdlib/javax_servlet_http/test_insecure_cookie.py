# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import java
from precli.rules import Rule
from tests.unit.rules import test_case


class TestInsecureCookie(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "JAV005"
        cls.parser = java.Java()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "java",
            "stdlib",
            "javax_servlet_http",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "insecure_cookie"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 614

    @pytest.mark.parametrize(
        "filename",
        [
            "CookieSecureFalse.java",
            "CookieSecureTrue.java",
        ],
    )
    def test(self, filename):
        self.check(filename)
