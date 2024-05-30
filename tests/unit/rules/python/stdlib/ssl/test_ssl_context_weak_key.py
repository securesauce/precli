# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules import test_case


class TestSslSocketWeakKey(test_case.TestCase):
    @classmethod
    def setup_class(cls):
        cls.rule_id = "PY019"
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "stdlib",
            "ssl",
            "examples",
        )

    def test_rule_meta(self):
        rule = Rule.get_by_id(self.rule_id)
        assert rule.id == self.rule_id
        assert rule.name == "inadequate_encryption_strength"
        assert (
            rule.help_url
            == f"https://docs.securesauce.dev/rules/{self.rule_id}"
        )
        assert rule.default_config.enabled is True
        assert rule.default_config.level == Level.WARNING
        assert rule.default_config.rank == -1.0
        assert rule.cwe.id == 326

    @pytest.mark.parametrize(
        "filename",
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
            "ssl_context_set_ecdh_curve_typed_default_param.py",
            "ssl_context_set_ecdh_curve_typed_param.py",
            "ssl_context_set_ecdh_curve_unverified_context.py",
        ],
    )
    def test(self, filename):
        self.check(filename)
