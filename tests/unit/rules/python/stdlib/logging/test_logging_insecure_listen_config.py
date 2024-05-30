# Copyright 2023 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestInsecureListenConfig(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY010"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "logging",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "code_injection"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 94

    @pytest.mark.parametrize(
        "filename",
        [
            "insecure_listen_config_empty_args.py",
            "insecure_listen_config_port.py",
            "insecure_listen_config_port_verify_as_var.py",
            "insecure_listen_config_port_verify_none.py",
            "insecure_listen_config_verify_none.py",
            "insecure_listen_config_verify_none_port.py",
            "insecure_listen_config_verify_set.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
