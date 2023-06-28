# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class JsonLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE0007")
        self.assertEqual("PRE0007", rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    def test_json_jsondecoder_decode(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "json_jsondecoder_decode.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(14, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_json_load(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "json_load.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_json_loads(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "json_loads.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0007", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(10, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
