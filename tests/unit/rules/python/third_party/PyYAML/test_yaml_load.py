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
