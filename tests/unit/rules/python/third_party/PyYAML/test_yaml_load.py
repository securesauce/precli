# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class YamlLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0521"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "PyYAML",
            "examples",
        )

    def test_yaml_load_rule_meta(self):
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
            "yaml_load",
            "yaml_load_from_import",
            "yaml_load_from_import_alias",
            "yaml_load_from_import_wildcard",
            "yaml_load_import_alias",
            "yaml_load_import_in_async_func",
            "yaml_load_import_in_class",
            "yaml_load_import_in_func",
            "yaml_load_import_in_loop",
            "yaml_load_importlib",
            "yaml_load_incomplete_import",
            "yaml_load_invalid_import",
            "yaml_load_kwarg_alias_loader",
            "yaml_load_kwarg_csafeloader",
            "yaml_load_kwarg_json_safeloader",
            "yaml_load_kwarg_loader",
            "yaml_load_kwarg_safeloader",
            "yaml_load_loader_as_var",
            "yaml_load_no_import",
            "yaml_load_positional_csafeloader",
            "yaml_load_positional_loader",
            "yaml_load_positional_safeloader",
            "yaml_load_yaml_as_identifier",
        ]
    )
    def test(self, filename):
        self.check(filename)
