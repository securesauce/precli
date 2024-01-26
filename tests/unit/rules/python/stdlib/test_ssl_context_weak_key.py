# Copyright 2024 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class SslSocketWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PY018"
        self.parser = python.Python()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        self.assertEqual(self.rule_id, rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual(
            f"https://docs.securesauce.dev/rules/{self.rule_id}", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    @parameterized.expand(
        [
            "ssl_context_set_ecdh_curve_brainpoolP256r1.py",
            "ssl_context_set_ecdh_curve_brainpoolP384r1.py",
            "ssl_context_set_ecdh_curve_brainpoolP384r1tls13.py",
            "ssl_context_set_ecdh_curve_brainpoolP512r1.py",
            "ssl_context_set_ecdh_curve_default_context.py",
            "ssl_context_set_ecdh_curve_ffdhe2048.py",
            "ssl_context_set_ecdh_curve_prime192v1.py",
            "ssl_context_set_ecdh_curve_prime256v1.py",
            "ssl_context_set_ecdh_curve_secp160r2.py",
            "ssl_context_set_ecdh_curve_secp256r1.py",
            "ssl_context_set_ecdh_curve_sect163k1.py",
            "ssl_context_set_ecdh_curve_sect571k1.py",
            "ssl_context_set_ecdh_curve_unverified_context.py",
        ]
    )
    def test(self, filename):
        self.check(filename)
