# Copyright 2023 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestGetServerCertificate(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY018"
        cls.parser = python.Python(skip_tests=False)
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "ssl",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "inadequate_encryption_strength"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.config.enabled is True
        assert rule.config.level == Level.ERROR
        assert rule.config.rank == -1.0
        assert rule.cwe.id == 326

    @pytest.mark.parametrize(
        "filename",
        [
            "get_server_certificate_sslv2.py",
            "get_server_certificate_sslv23.py",
            "get_server_certificate_sslv3.py",
            "get_server_certificate_tlsv1.py",
            "get_server_certificate_tlsv11.py",
            "get_server_certificate_tlsv12.py",
        ],
    )
    def test(self, filename):
        self.check(filename, enabled=[self.rule_id])
