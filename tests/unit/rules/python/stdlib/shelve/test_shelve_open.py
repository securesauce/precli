# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestShelveOpen(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY015"
        cls.parser = python.Python(skip_tests=False)
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "shelve",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "deserialization_of_untrusted_data"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.config.enabled is True
        assert rule.config.level == Level.WARNING
        assert rule.config.rank == -1.0
        assert rule.cwe.id == 502

    @pytest.mark.parametrize(
        "filename",
        [
            "shelve_dbfilenameshelf.py",
            "shelve_open.py",
            "shelve_open_context_mgr.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
