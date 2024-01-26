# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class SmtpCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY015"
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
            "smtplib_smtp_auth.py",
            "smtplib_smtp_context_mgr.py",
            "smtplib_smtp_login.py",
            "smtplib_smtp_ssl.py",
            "smtplib_smtp_starttls.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
