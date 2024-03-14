# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class HttpUrlSecretTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY007"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "http",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("sensitive_query_strings", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.ERROR, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("598", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "http_url_secret_apikey.py",
            "http_url_secret_apikey_in_header.py",
            "http_url_secret_basic_auth.py",
            "http_url_secret_basic_auth_as_var.py",
            "http_url_secret_password.py",
            "http_url_secret_username.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
