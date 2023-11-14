# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class ImapCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0007"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "imaplib",
            "examples",
        )

    def test_imap_cleartext_rule_meta(self):
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
            "imaplib_imap4_authenticate",
            "imaplib_imap4_context_mgr",
            "imaplib_imap4_login",
            "imaplib_imap4_login_cram_md5",
            "imaplib_imap4_ssl",
            "imaplib_imap4_starttls",
            "imaplib_imap4_stream",
        ]
    )
    def test(self, filename):
        self.check(filename)
