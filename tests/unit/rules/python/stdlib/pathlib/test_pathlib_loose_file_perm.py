# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestPathlibLooseFilePermissions(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY037"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "pathlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "incorrect_permission"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 732

    @pytest.mark.parametrize(
        "filename",
        [
            "pathlib_chmod_IXOTH.py",
            "pathlib_chmod_o111_binop_wildcard.py",
            "pathlib_chmod_o644.py",
            "pathlib_chmod_o7.py",
            "pathlib_chmod_o755_binop_stat.py",
            "pathlib_chmod_o760.py",
            "pathlib_chmod_o770.py",
            "pathlib_chmod_o776.py",
            "pathlib_chmod_o777.py",
            "pathlib_chmod_S_IXOTH.py",
            "pathlib_chmod_S_S_IXOTH.py",
            "pathlib_chmod_stat_S_IXOTH.py",
            "pathlib_chmod_x1ff.py",
            "pathlib_lchmod_o227.py",
            "pathlib_mkdir_default.py",
            "pathlib_mkdir_o750_binop.py",
            "pathlib_touch_default.py",
            "pathlib_touch_o750_binop.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
