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
            "requests",
            "examples",
        )

    def test_no_certificate_verify_rule_meta(self):
        rule = Rule.get_by_id("PRE312")
        self.assertEqual("PRE312", rule.id)
        self.assertEqual("improper_certificate_validation", rule.name)
        self.assertEqual("", rule.help_url)
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("295", rule.cwe.cwe_id)

    def test_requests_delete_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_delete_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(50, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_get_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_get_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(47, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_get_verify_true(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_get_verify_true.py")
        )
        self.assertEqual(0, len(results))

    def test_requests_get_verify_unset(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_get_verify_unset.py")
        )
        self.assertEqual(0, len(results))

    def test_requests_head_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_head_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_options_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_options_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(51, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_patch_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_patch_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(49, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_post_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_post_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_put_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_put_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(47, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_request_verify_false(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "requests_request_verify_false.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(58, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_as_context_get_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path,
                "requests_session_as_context_get_verify_false.py",
            )
        )
        # TODO(ericwb): false negative
        self.assertEqual(0, len(results))

    def test_requests_session_delete_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_delete_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(49, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_get_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_get_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(46, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_head_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_head_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(47, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_options_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_options_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(50, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_patch_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_patch_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(48, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_post_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_post_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(47, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_put_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_put_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(46, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_requests_session_request_verify_false(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "requests_session_request_verify_false.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE312", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(0, result.location.start_column)
        self.assertEqual(57, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
