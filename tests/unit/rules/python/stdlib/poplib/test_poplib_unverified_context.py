# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestPoplibUnverifiedContext(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY025"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "poplib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "improper_certificate_validation"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 295

    @pytest.mark.parametrize(
        "filename",
        [
            "poplib_pop3_ssl_context_as_var.py",
            "poplib_pop3_ssl_context_none.py",
            "poplib_pop3_ssl_context_unset.py",
            "poplib_pop3_stls_context_as_var.py",
            "poplib_pop3_stls_context_none.py",
            "poplib_pop3_stls_context_unset.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
