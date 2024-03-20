# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class ReDenialOfService(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY033"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "re",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("regex_denial_of_service", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.ERROR, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("1333", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "re_compile.py",
            "re_compile_good.py",
            "re_search.py",
            "re_search_good.py",
            "re_match.py",
            "re_fullmatch.py",
            "re_split.py",
            "re_findall.py",
            "re_finditer.py",
            "re_sub.py",
            "re_subn.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
