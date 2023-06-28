# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class HmacTimingAttackTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "hmac",
            "examples",
        )

    def test_hmac_timing_attack_rule_meta(self):
        rule = Rule.get_by_id("PRE0005")
        self.assertEqual("PRE0005", rule.id)
        self.assertEqual("observable_timing_discrepancy", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("208", rule.cwe.cwe_id)

    def test_hmac_timing_attack(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_timing_attack.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(13, result.location.start_line)
        self.assertEqual(13, result.location.end_line)
        self.assertEqual(7, result.location.start_column)
        self.assertEqual(13, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_timing_attack_class(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "hmac_timing_attack_class.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(14, result.location.start_line)
        self.assertEqual(14, result.location.end_line)
        self.assertEqual(7, result.location.start_column)
        self.assertEqual(13, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_timing_attack_class_hexdigest(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_timing_attack_class_hexdigest.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0005", result.rule_id)
        self.assertEqual(11, result.location.start_line)
        self.assertEqual(11, result.location.end_line)
        self.assertEqual(7, result.location.start_column)
        self.assertEqual(13, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_hmac_timing_attack_compare_digest(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "hmac_timing_attack_compare_digest.py"
            )
        )
        self.assertEqual(0, len(results))
