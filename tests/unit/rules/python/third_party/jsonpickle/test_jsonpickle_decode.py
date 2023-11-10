# Copyright 2023 Secure Saurce LLC
import textwrap

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


RULE_ID = "PRE0507"


class JsonPickleDecodeTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python(enabled=[RULE_ID])

    def test_jsonpickle_decode_rule_meta(self):
        rule = Rule.get_by_id(RULE_ID)
        self.assertEqual(RULE_ID, rule.id)
        self.assertEqual("deserialization_of_untrusted_data", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{RULE_ID}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("502", rule.cwe.cwe_id)

    def test_jsonpickle_decode(self):
        fdata = textwrap.dedent(
            """
            import jsonpickle
            pick = jsonpickle.encode({'a': 'b', 'c': 'd'})
            jsonpickle.decode(pick)
            """
        )
        results = self.parser.parse("test.py", str.encode(fdata))
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual(RULE_ID, result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(17, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        # self.assertEqual("", result.message)
        self.assertEqual(-1.0, result.rank)
        # self.assertEqual(, result.fixes)
