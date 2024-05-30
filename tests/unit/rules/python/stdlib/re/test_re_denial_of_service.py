# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestReDenialOfService(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY033"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "re",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "regex_denial_of_service"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 1333

    @pytest.mark.parametrize(
        "filename",
        [
            "re_compile.py",
            "re_compile_good.py",
            "re_search.py",
            "re_search_good.py",
            "re_match.py",
            "re_fullmatch.py",
            "re_split.py",
            "re_findall.py",
            "re_finditer.py",
            "re_sub.py",
            "re_subn.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
