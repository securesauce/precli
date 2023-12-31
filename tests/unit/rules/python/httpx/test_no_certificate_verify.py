# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class NoCertificateVerifyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY507"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "httpx",
            "examples",
        )

    def test_no_certificate_verify_rule_meta(self):
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
            "httpx_async_client_as_context_verify_false",
            "httpx_async_client_verify_false",
            "httpx_client_as_context_verify_false",
            "httpx_client_verify_false",
            "httpx_delete_verify_false",
            "httpx_get_verify_false",
            "httpx_get_verify_true",
            "httpx_get_verify_unset",
            "httpx_head_verify_false",
            "httpx_options_verify_false",
            "httpx_patch_verify_false",
            "httpx_post_verify_false",
            "httpx_put_verify_false",
            "httpx_request_verify_false",
            "httpx_stream_verify_false",
        ]
    )
    def test(self, filename):
        self.check(filename)
