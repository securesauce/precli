# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestJsonLoad(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY009"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "json",
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
        assert rule.default_config.enabled is False
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 502

    @pytest.mark.parametrize(
        "filename",
        [
            "json_jsondecoder_decode.py",
            "json_load.py",
            "json_loads.py",
        ],
    )
    def test(self, filename):
        self.check(filename, enabled=[self.rule_id])
