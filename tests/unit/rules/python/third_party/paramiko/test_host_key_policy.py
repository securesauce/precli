# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class HostKeyPolicyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0510"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "paramiko",
            "examples",
        )

    def expected(self, filename):
        with open(os.path.join(self.base_path, f"{filename}.py")) as f:
            level = f.readline().strip()
            level = level.removeprefix("# level: ")
            level = getattr(Level, level)
            if level != Level.NONE:
                start_line = f.readline().strip()
                start_line = int(start_line.removeprefix("# start_line: "))
                end_line = f.readline().strip()
                end_line = int(end_line.removeprefix("# end_line: "))
                start_col = f.readline().strip()
                start_col = int(start_col.removeprefix("# start_column: "))
                end_col = f.readline().strip()
                end_col = int(end_col.removeprefix("# end_column: "))
            else:
                start_line = end_line = start_col = end_col = -1

        return (level, start_line, end_line, start_col, end_col)

    def test_paramiko_no_host_key_verify_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "host_key_auto_add_policy",
            "host_key_auto_add_policy_import_paramiko",
            "host_key_auto_add_policy_in_func",
            "host_key_auto_add_policy_kwarg",
            "host_key_auto_add_policy_single_statement",
            "host_key_auto_add_policy_walrus",
            "host_key_warning_policy_single_statement",
        ]
    )
    def test(self, filename):
        (
            level,
            start_line,
            end_line,
            start_column,
            end_column,
        ) = self.expected(filename)
        results = self.parser.parse(
            os.path.join(self.base_path, f"{filename}.py")
        )
        if level == Level.NONE:
            self.assertEqual(0, len(results))
        else:
            self.assertEqual(1, len(results))
            result = results[0]
            self.assertEqual(self.rule_id, result.rule_id)
            self.assertEqual(start_line, result.location.start_line)
            self.assertEqual(end_line, result.location.end_line)
            self.assertEqual(start_column, result.location.start_column)
            self.assertEqual(end_column, result.location.end_column)
            self.assertEqual(level, result.level)
            self.assertEqual(-1.0, result.rank)
