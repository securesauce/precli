# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class SslContextTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY519"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "pyopenssl",
            "examples",
        )

    def test_ssl_context_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "ssl_context_sslv2",
            "ssl_context_sslv23",
            "ssl_context_sslv3",
            "ssl_context_tlsv1",
            "ssl_context_tlsv11",
            "ssl_context_tlsv12",
        ]
    )
    def test(self, filename):
        self.check(filename)
