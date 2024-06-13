# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestArgparseSensitiveInfo(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY027"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "argparse",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "visible_sensitive_information"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 214

    @pytest.mark.parametrize(
        "filename",
        [
            "argparse_add_argument_api_key.py",
            "argparse_add_argument_default_action.py",
            "argparse_add_argument_password.py",
            "argparse_add_argument_password_file.py",
            "argparse_add_argument_password_store_true.py",
            "argparse_add_argument_token.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
