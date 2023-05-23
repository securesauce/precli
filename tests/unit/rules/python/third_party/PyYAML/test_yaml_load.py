# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class YamlLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
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
        rule = Rule.get_by_id("PRE311")
        self.assertEqual("PRE311", rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    def test_yaml_load(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        # self.assertEqual("", result.message)
        self.assertEqual(-1.0, result.rank)
        # self.assertEqual(, result.fixes)

    def test_yaml_load_import_alias(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_import_alias.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(8, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_from_import(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_from_import.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(4, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_from_import_alias(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_from_import_alias.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(8, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_from_import_wildcard(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_from_import_wildcard.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(4, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_importlib(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_importlib.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(9, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_no_import(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_no_import.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_invalid_import(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_invalid_import.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_incomplete_import(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_incomplete_import.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_import_in_async_func(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_import_in_async_func.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_import_in_class(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_import_in_class.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_import_in_func(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_import_in_func.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_import_in_loop(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_import_in_loop.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(16, result.location.start_column)
        self.assertEqual(27, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_positional_loader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_positional_loader.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(16, result.location.start_column)
        self.assertEqual(22, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_positional_safeloader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_positional_safeloader.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_positional_csafeloader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_positional_csafeloader.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_loader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_kwarg_loader.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(23, result.location.start_column)
        self.assertEqual(34, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_kwarg_safeloader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_kwarg_safeloader.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_csafeloader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_kwarg_csafeloader.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_alias_loader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_kwarg_alias_loader.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(23, result.location.start_column)
        self.assertEqual(29, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_kwarg_json_safeloader(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_kwarg_json_safeloader.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE311", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(23, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_loader_as_var(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_loader_as_var.py")
        )
        self.assertEqual(0, len(results))

    def test_yaml_load_yaml_as_identifier(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "yaml_load_yaml_as_identifier.py")
        )
        self.assertEqual(0, len(results))
