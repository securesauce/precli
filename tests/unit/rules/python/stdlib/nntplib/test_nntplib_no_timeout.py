# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestNntplibNoTimeout(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY042"
        cls.parser = python.Python(skip_tests=False)
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "nntplib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "no_timeout"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.config.enabled is True
        assert rule.config.level == Level.WARNING
        assert rule.config.rank == -1.0
        assert rule.cwe.id == 1088

    @pytest.mark.parametrize(
        "filename",
        [
            "nntplib_nntp_ssl_no_timeout.py",
            "nntplib_nntp_ssl_timeout_5.py",
            "nntplib_nntp_timeout_global.py",
            "nntplib_nntp_timeout_none.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
