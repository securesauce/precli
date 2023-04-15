# Copyright 2023 Secure Saurce LLC
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class YamlLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()

    def test_yaml_load_rule_meta(self):
        rule = Rule.get_by_id("PRE317")
        self.assertEqual("PRE317", rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    def test_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(2, result.location.start_line)
        self.assertEqual(2, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(15, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        # self.assertEqual("", result.message)
        self.assertEqual(-1.0, result.rank)
        # self.assertEqual(, result.fixes)

    def test_import_alias_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml.load as yamlload
            yamlload("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(2, result.location.start_line)
        self.assertEqual(2, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(14, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_from_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            from yaml import load
            load("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(2, result.location.start_line)
        self.assertEqual(2, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(10, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_from_import_alias_yaml_load(self):
        fdata = textwrap.dedent(
            """
            from yaml import load as yamlload
            yamlload("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(2, result.location.start_line)
        self.assertEqual(2, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(14, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_no_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            yaml.load("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_invalid_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import json as yaml
            yaml.load("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_incomplete_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml
            load("{}")
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_positional_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import Loader
            yaml.load("{}", Loader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(23, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_positional_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.SafeLoader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_positional_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.CSafeLoader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.Loader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(2, result.location.start_line)
        self.assertEqual(2, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(35, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_kwarg_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import SafeLoader
            yaml.load("{}", Loader=SafeLoader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.CSafeLoader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_alias_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import Loader as LOADER
            yaml.load("{}", Loader=LOADER)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_yaml_load_kwarg_json_safeloader(self):
        fdata = textwrap.dedent(
            """
            import json
            import yaml
            yaml.load("{}", Loader=json.SafeLoader)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE317", result.rule_id)
        self.assertEqual(3, result.location.start_line)
        self.assertEqual(3, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(39, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)
