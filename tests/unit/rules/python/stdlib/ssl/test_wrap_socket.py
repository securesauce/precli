# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class WrapSocketTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY017"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "ssl",
            "examples",
        )

    def test_wrap_socket_rule_meta(self):
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
            "wrap_socket_sslv2",
            "wrap_socket_sslv23",
            "wrap_socket_sslv2_server_side_true",
            "wrap_socket_sslv3",
            "wrap_socket_tlsv1",
            "wrap_socket_tlsv11",
            "wrap_socket_tlsv12",
        ]
    )
    def test(self, filename):
        self.check(filename)
