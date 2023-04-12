# Copyright 2023 Secure Saurce LLC
import textwrap

from precli.core.level import Level
from tests.unit.rules.python import test_case


class YamlLoadTests(test_case.TestCase):
    def setUp(self):
        super().setUp()

    def test_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_import_alias_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml.load as yamlload
            yamlload("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_from_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            from yaml import load
            load("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_from_import_alias_yaml_load(self):
        fdata = textwrap.dedent(
            """
            from yaml import load as yamlload
            yamlload("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_no_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            yaml.load("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_invalid_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import json as yaml
            yaml.load("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_incomplete_import_yaml_load(self):
        fdata = textwrap.dedent(
            """
            import yaml
            load("{}")
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_positional_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import Loader
            yaml.load("{}", Loader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_yaml_load_positional_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.SafeLoader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_positional_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", yaml.CSafeLoader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.Loader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_yaml_load_kwarg_safeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import SafeLoader
            yaml.load("{}", Loader=SafeLoader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            yaml.load("{}", Loader=yaml.CSafeLoader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(0, len(results))

    def test_yaml_load_kwarg_alias_loader(self):
        fdata = textwrap.dedent(
            """
            import yaml
            from yaml import Loader as LOADER
            yaml.load("{}", Loader=LOADER)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)

    def test_yaml_load_kwarg_csafeloader(self):
        fdata = textwrap.dedent(
            """
            import json
            import yaml
            yaml.load("{}", Loader=json.SafeLoader)
            """
        )
        results = self.parser.parse(str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE1010", result.rule_id)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual("", result.message)
