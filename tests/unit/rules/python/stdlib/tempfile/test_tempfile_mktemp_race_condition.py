# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class MktempRaceConditionTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY021"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "tempfile",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("insecure_temporary_file", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("377", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "tempfile_mktemp.py",
            "tempfile_mktemp_args_open.py",
            "tempfile_mktemp_args_with_open_args.py",
            "tempfile_mktemp_open.py",
            "tempfile_mktemp_walrus_open.py",
            "tempfile_mktemp_with_open.py",
            "tempfile_mktemp_with_open_multiline.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
