# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestFtpCleartext(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY003"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "ftplib",
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
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 319

    @pytest.mark.parametrize(
        "filename",
        [
            "ftp.py",
            "ftp_context_mgr.py",
            "ftp_tls.py",
            "ftplib_ftp.py",
            "ftplib_ftp_context_mgr.py",
            "ftplib_ftp_tls.py",
            "ftplib_ftp_user_password.py",
            "ftplib_ftp_tls_user_password.py",
        ],
    )
    def test(self, filename):
        self.check(filename)

    def test_ftp_login(self):
        artifact = Artifact(os.path.join(self.base_path, "ftp_login.py"))
        results = self.parser.parse(artifact)
        assert len(results) == 2
        result = results[0]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 6
        assert result.location.end_column == 9
        assert result.level == Level.WARNING
        assert result.rank == -1.0
        result = results[1]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 5
        assert result.location.end_line == 5
        assert result.location.start_column == 4
        assert result.location.end_column == 9
        assert result.level == Level.ERROR
        assert result.rank == -1.0

    def test_ftplib_ftp_login(self):
        artifact = Artifact(
            os.path.join(self.base_path, "ftplib_ftp_login.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 2
        result = results[0]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 6
        assert result.location.end_column == 16
        assert result.level == Level.WARNING
        assert result.rank == -1.0
        result = results[1]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 5
        assert result.location.end_line == 5
        assert result.location.start_column == 4
        assert result.location.end_column == 9
        assert result.level == Level.ERROR
        assert result.rank == -1.0

    def test_ftplib_ftp_login_single_statement(self):
        artifact = Artifact(
            os.path.join(
                self.base_path, "ftplib_ftp_login_single_statement.py"
            )
        )
        results = self.parser.parse(artifact)
        assert len(results) == 2
        result = results[0]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 32
        assert result.location.end_column == 37
        assert result.level == Level.ERROR
        assert result.rank == -1.0
        result = results[1]
        assert result.rule_id == self.rule_id
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 0
        assert result.location.end_column == 10
        assert result.level == Level.WARNING
        assert result.rank == -1.0
