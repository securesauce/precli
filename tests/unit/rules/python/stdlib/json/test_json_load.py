# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.rules import Rule
from tests.unit.rules.python import test_case


class JsonLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY008"
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "json",
            "examples",
        )

    def test_json_load_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "json_jsondecoder_decode",
            "json_load",
            "json_loads",
        ]
    )
    def test(self, filename):
        self.check(filename)
