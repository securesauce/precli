# Copyright 2023 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestTelnetlibCleartext(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY020"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "telnetlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "cleartext_transmission"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 319

    @pytest.mark.parametrize(
        "filename",
        [
            "telnet.py",
            "telnetlib_telnet.py",
            "telnetlib_telnet_context_mgr.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
