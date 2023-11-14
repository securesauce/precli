# Copyright 2023 Secure Saurce LLC
import os

from parameterized import parameterized

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class CryptographyWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.rule_id = "PRE0504"
        self.parser = python.Python(enabled=[self.rule_id])
        self.base_path = os.path.join(
            "tests",
            "unit",
            "rules",
            "python",
            "third_party",
            "cryptography",
            "examples",
        )

    def test_cryptography_weak_key_rule_meta(self):
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
            "dsa_generate_parameters_1024",
            "dsa_generate_parameters_2048",
            "dsa_generate_parameters_4096",
            "dsa_generate_parameters_kwarg_1024",
            "dsa_generate_parameters_kwarg_2048",
            "dsa_generate_parameters_kwarg_4096",
            "dsa_generate_parameters_var_1024",
            "dsa_generate_private_key_1024",
            "dsa_generate_private_key_2048",
            "dsa_generate_private_key_4096",
            "dsa_generate_private_key_kwarg_1024",
            "dsa_generate_private_key_kwarg_2048",
            "dsa_generate_private_key_kwarg_4096",
            "dsa_generate_private_key_var_1024",
            "ec_derive_private_key_brainpoolp256r1",
            "ec_derive_private_key_brainpoolp384r1",
            "ec_derive_private_key_brainpoolp512r1",
            "ec_derive_private_key_secp192r1",
            "ec_derive_private_key_secp224r1",
            "ec_derive_private_key_secp256k1",
            "ec_derive_private_key_secp256r1",
            "ec_derive_private_key_secp384r1",
            "ec_derive_private_key_secp521r1",
            "ec_derive_private_key_sect163k1",
            "ec_derive_private_key_sect163r2",
            "ec_derive_private_key_sect233k1",
            "ec_derive_private_key_sect233r1",
            "ec_derive_private_key_sect283k1",
            "ec_derive_private_key_sect283r1",
            "ec_derive_private_key_sect409k1",
            "ec_derive_private_key_sect409r1",
            "ec_derive_private_key_sect571k1",
            "ec_derive_private_key_sect571r1",
            "ec_generate_private_key_brainpoolp256r1",
            "ec_generate_private_key_brainpoolp384r1",
            "ec_generate_private_key_brainpoolp512r1",
            "ec_generate_private_key_secp192r1",
            "ec_generate_private_key_secp224r1",
            "ec_generate_private_key_secp256k1",
            "ec_generate_private_key_secp256r1",
            "ec_generate_private_key_secp384r1",
            "ec_generate_private_key_secp521r1",
            "ec_generate_private_key_sect163k1",
            "ec_generate_private_key_sect163r2",
            "ec_generate_private_key_sect233k1",
            "ec_generate_private_key_sect233r1",
            "ec_generate_private_key_sect283k1",
            "ec_generate_private_key_sect283r1",
            "ec_generate_private_key_sect409k1",
            "ec_generate_private_key_sect409r1",
            "ec_generate_private_key_sect571k1",
            "ec_generate_private_key_sect571r1",
            "rsa_generate_private_key_1024",
            "rsa_generate_private_key_2048",
            "rsa_generate_private_key_4096",
            "rsa_generate_private_key_kwarg_1024",
            "rsa_generate_private_key_kwarg_2048",
            "rsa_generate_private_key_kwarg_4096",
            "rsa_generate_private_key_var_1024",
        ]
    )
    def test(self, filename):
        self.check(filename)
