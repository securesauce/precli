# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class ImapCleartextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE0007")
        self.assertEqual("PRE0007", rule.id)
        self.assertEqual("cleartext_transmission", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("319", rule.cwe.cwe_id)

    def test_imaplib_imap4_authenticate(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_authenticate.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(7, result.location.start_line)
        self.assertEqual(7, result.location.end_line)
        self.assertEqual(6, result.location.start_column)
        self.assertEqual(18, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_imaplib_imap4_context_mgr(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_context_mgr.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(10, result.location.start_column)
        self.assertEqual(15, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_imaplib_imap4_login(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_login.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(6, result.location.start_column)
        self.assertEqual(11, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_imaplib_imap4_login_cram_md5(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_login_cram_md5.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(6, result.location.start_column)
        self.assertEqual(20, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_imaplib_imap4_ssl(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_ssl.py")
        )
        self.assertEqual(0, len(results))

    def test_imaplib_imap4_starttls(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_starttls.py")
        )
        self.assertEqual(0, len(results))

    def test_imaplib_imap4_stream(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "imaplib_imap4_stream.py")
        )
        self.assertEqual(0, len(results))
