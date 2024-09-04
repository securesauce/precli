# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestOsLooseFilePermissions(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY036"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "os",
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
            "os_chmod_IXOTH.py",
            "os_chmod_o111_binop_wildcard.py",
            "os_chmod_o555_augmented.py",
            "os_chmod_o555_binop.py",
            "os_chmod_o644.py",
            "os_chmod_o7.py",
            "os_chmod_o755_binop_stat.py",
            "os_chmod_o760.py",
            "os_chmod_o770.py",
            "os_chmod_o776.py",
            "os_chmod_o777.py",
            "os_chmod_S_IXOTH.py",
            "os_chmod_S_S_IXOTH.py",
            "os_chmod_stat_S_IXOTH.py",
            "os_chmod_x1ff.py",
            "os_fchmod_511.py",
            "os_lchmod_o227.py",
            "os_mkdir_default.py",
            "os_mkdir_o750_binop.py",
            "os_mkfifo_default.py",
            "os_mkfifo_o644_binop.py",
            "os_mknod_o666_binop.py",
            "os_open_default.py",
            "os_open_o655.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
