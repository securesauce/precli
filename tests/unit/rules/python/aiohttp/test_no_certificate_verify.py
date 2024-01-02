# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class NoCertificateVerifyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY501"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "aiohttp",
            "examples",
        )

    def test_no_certificate_verify_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "session_delete_ssl_false.py",
            "session_delete_verify_ssl_false.py",
            "session_get_ssl_false.py",
            "session_get_ssl_true.py",
            "session_get_ssl_unset.py",
            "session_get_verify_ssl_false.py",
            "session_get_verify_ssl_true.py",
            "session_head_ssl_false.py",
            "session_head_verify_ssl_false.py",
            "session_options_ssl_false.py",
            "session_options_verify_ssl_false.py",
            "session_patch_ssl_false.py",
            "session_patch_verify_ssl_false.py",
            "session_post_ssl_false.py",
            "session_post_verify_ssl_false.py",
            "session_put_ssl_false.py",
            "session_put_verify_ssl_false.py",
            "session_request_ssl_false.py",
            "session_request_verify_ssl_false.py",
            "session_ws_connect_ssl_false.py",
            "session_ws_connect_verify_ssl_false.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
