# Copyright 2023 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestMktempRaceCondition(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY021"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "tempfile",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "insecure_temporary_file"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 377

    @pytest.mark.parametrize(
        "filename",
        [
            "tempfile_mktemp.py",
            "tempfile_mktemp_args_open.py",
            "tempfile_mktemp_args_with_open_args.py",
            "tempfile_mktemp_open.py",
            "tempfile_mktemp_walrus_open.py",
            "tempfile_mktemp_with_open.py",
            "tempfile_mktemp_with_open_multiline.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
