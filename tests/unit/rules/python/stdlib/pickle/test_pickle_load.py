# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestPickleLoad(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY013"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "pickle",
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
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.cwe_id == "502"

    @pytest.mark.parametrize(
        "filename",
        [
            "pickle_load.py",
            "pickle_loads.py",
            "pickle_unpickler.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
