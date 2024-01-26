# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class InsecureListenConfigTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY009"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
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
            "insecure_listen_config_empty_args.py",
            "insecure_listen_config_port.py",
            "insecure_listen_config_port_verify_as_var.py",
            "insecure_listen_config_port_verify_none.py",
            "insecure_listen_config_verify_none.py",
            "insecure_listen_config_verify_none_port.py",
            "insecure_listen_config_verify_set.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
