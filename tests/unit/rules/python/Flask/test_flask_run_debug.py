# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class FlaskRunDebugTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY507"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "Flask",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("code_injection", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("94", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "flask_run_debug_as_var.py",
            "flask_run_debug_false.py",
            "flask_run_debug_true.py",
            "flask_run_debug_unset.py",
            "flask_run_debug_wildcard.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
