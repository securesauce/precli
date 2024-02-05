# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class FtpCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY003"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("cleartext_transmission", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("319", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "ftp.py",
            "ftp_tls.py",
            "ftplib_ftp.py",
            "ftplib_ftp_context_mgr.py",
            "ftplib_ftp_tls.py",
            "ftplib_ftp_user_password.py",
            "ftplib_ftp_tls_user_password.py",
        ]
    )
    def test(self, filename):
        self.check(filename)

    def test_ftp_login(self):
        artifact = Artifact(os.path.join(self.base_path, "ftp_login.py"))
        results = self.parser.parse(artifact)
        self.assertEqual(2, len(results))
        result = results[0]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(6, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
        result = results[1]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(4, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ftplib_ftp_login(self):
        artifact = Artifact(
            os.path.join(self.base_path, "ftplib_ftp_login.py")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(2, len(results))
        result = results[0]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(6, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
        result = results[1]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(4, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ftplib_ftp_login_single_statement(self):
        artifact = Artifact(
            os.path.join(
                self.base_path, "ftplib_ftp_login_single_statement.py"
            )
        )
        results = self.parser.parse(artifact)
        self.assertEqual(2, len(results))
        result = results[0]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(32, result.location.start_column)
        self.assertEqual(37, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
        result = results[1]
        self.assertEqual(self.rule_id, result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(10, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
