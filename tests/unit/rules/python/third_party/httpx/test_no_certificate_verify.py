# Copyright 2023 Secure Saurce LLC
import os
import textwrap

from precli.core.level import Level
from precli.core.rule import Rule
from tests.unit.rules.python import test_case


class NoCertificateVerifyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "httpx",
            "examples",
        )

    def test_no_certificate_verify_rule_meta(self):
        rule = Rule.get_by_id("PRE303")
        self.assertEqual("PRE303", rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    def test_httpx_async_client_as_context_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "httpx_async_client_as_context_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(36, result.location.start_column)
        self.assertEqual(41, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_async_client_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_async_client_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(34, result.location.start_column)
        self.assertEqual(39, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_client_as_context_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "httpx_client_as_context_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(25, result.location.start_column)
        self.assertEqual(30, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_client_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_client_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(29, result.location.start_column)
        self.assertEqual(34, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_delete_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_delete_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(41, result.location.start_column)
        self.assertEqual(46, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_get_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_get_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(38, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_get_verify_true(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_get_verify_true.py")
        )
        self.assertEqual(0, len(results))

    def test_httpx_get_verify_unset(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_get_verify_unset.py")
        )
        self.assertEqual(0, len(results))

    def test_httpx_head_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_head_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(39, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_options_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_options_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(42, result.location.start_column)
        self.assertEqual(47, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_patch_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_patch_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(40, result.location.start_column)
        self.assertEqual(45, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_post_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_post_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(39, result.location.start_column)
        self.assertEqual(44, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_put_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_put_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(38, result.location.start_column)
        self.assertEqual(43, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_request_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_request_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(48, result.location.start_column)
        self.assertEqual(53, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_httpx_stream_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "httpx_stream_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE303", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(41, result.location.start_column)
        self.assertEqual(46, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
