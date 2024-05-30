# Copyright 2023 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestHmacTimingAttack(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY005"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hmac",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "observable_timing_discrepancy"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.ERROR
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 208

    @pytest.mark.parametrize(
        "filename",
        [
            "hmac_timing_attack.py",
            "hmac_timing_attack_class.py",
            "hmac_timing_attack_class_hexdigest.py",
            "hmac_timing_attack_compare_digest.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
