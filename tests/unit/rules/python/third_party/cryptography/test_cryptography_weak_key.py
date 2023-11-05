# Copyright 2023 Secure Saurce LLC
import os

from precli.core.level import Level
from precli.parsers import python
from precli.rules import Rule
from tests.unit.rules.python import test_case


class CryptographyWeakKeyTests(test_case.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = python.Python(enabled=["PRE0502"])
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
        rule = Rule.get_by_id("PRE0502")
        self.assertEqual("PRE0502", rule.id)
        self.assertEqual("inadequate_encryption_strength", rule.name)
        self.assertEqual(
            "https://docs.securesauce.dev/rules/PRE0502", rule.help_url
        )
        self.assertEqual(True, rule.default_config.enabled)
        self.assertEqual(Level.WARNING, rule.default_config.level)
        self.assertEqual(-1.0, rule.default_config.rank)
        self.assertEqual("326", rule.cwe.cwe_id)

    def test_dsa_generate_parameters_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(24, result.location.start_column)
        self.assertEqual(28, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_parameters_2048(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_2048.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_4096(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_4096.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_kwarg_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(33, result.location.start_column)
        self.assertEqual(37, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_parameters_kwarg_2048(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_2048.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_kwarg_4096(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_parameters_kwarg_4096.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_parameters_var_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_parameters_var_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(24, result.location.start_column)
        self.assertEqual(31, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(25, result.location.start_column)
        self.assertEqual(29, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_2048(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_2048.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_4096(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "dsa_generate_private_key_4096.py")
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_kwarg_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(34, result.location.start_column)
        self.assertEqual(38, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_dsa_generate_private_key_kwarg_2048(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_2048.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_kwarg_4096(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_kwarg_4096.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_dsa_generate_private_key_var_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "dsa_generate_private_key_var_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(5, result.location.start_line)
        self.assertEqual(5, result.location.end_line)
        self.assertEqual(25, result.location.start_column)
        self.assertEqual(32, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_derive_private_key_brainpoolp256r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_derive_private_key_brainpoolp256r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_brainpoolp384r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_derive_private_key_brainpoolp384r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_brainpoolp512r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_derive_private_key_brainpoolp512r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_secp192r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp192r1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_derive_private_key_secp224r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp224r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_secp256k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp256k1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_secp256r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp256r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_secp384r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp384r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_secp521r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_secp521r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect163k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect163k1.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_derive_private_key_sect163r2(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect163r2.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(37, result.location.start_column)
        self.assertEqual(42, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_derive_private_key_sect233k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect233k1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect233r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect233r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect283k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect283k1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect283r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect283r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect409k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect409k1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect409r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect409r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect571k1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect571k1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_derive_private_key_sect571r1(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "ec_derive_private_key_sect571r1.py")
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_brainpoolp256r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_brainpoolp256r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_brainpoolp384r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_brainpoolp384r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_brainpoolp512r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_brainpoolp512r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_secp192r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp192r1.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(27, result.location.start_column)
        self.assertEqual(36, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_generate_private_key_secp224r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp224r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_secp256k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp256k1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_secp256r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp256r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_secp384r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp384r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_secp521r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_secp521r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect163k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect163k1.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(27, result.location.start_column)
        self.assertEqual(36, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_generate_private_key_sect163r2(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect163r2.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(27, result.location.start_column)
        self.assertEqual(36, result.location.end_column)
        self.assertEqual(Level.WARNING, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_ec_generate_private_key_sect233k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect233k1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect233r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect233r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect283k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect283k1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect283r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect283r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect409k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect409k1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect409r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect409r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect571k1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect571k1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_ec_generate_private_key_sect571r1(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "ec_generate_private_key_sect571r1.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_rsa_generate_private_key_1024(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "rsa_generate_private_key_1024.py")
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(32, result.location.start_column)
        self.assertEqual(36, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_rsa_generate_private_key_2048(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "rsa_generate_private_key_2048.py")
        )
        self.assertEqual(0, len(results))

    def test_rsa_generate_private_key_4096(self):
        results = self.parser.parse(
            os.path.join(self.base_path, "rsa_generate_private_key_4096.py")
        )
        self.assertEqual(0, len(results))

    def test_rsa_generate_private_key_kwarg_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "rsa_generate_private_key_kwarg_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(4, result.location.start_line)
        self.assertEqual(4, result.location.end_line)
        self.assertEqual(57, result.location.start_column)
        self.assertEqual(61, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_rsa_generate_private_key_kwarg_2048(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "rsa_generate_private_key_kwarg_2048.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_rsa_generate_private_key_kwarg_4096(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "rsa_generate_private_key_kwarg_4096.py"
            )
        )
        self.assertEqual(0, len(results))

    def test_rsa_generate_private_key_var_1024(self):
        results = self.parser.parse(
            os.path.join(
                self.base_path, "rsa_generate_private_key_var_1024.py"
            )
        )
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("PRE0502", result.rule_id)
        self.assertEqual(6, result.location.start_line)
        self.assertEqual(6, result.location.end_line)
        self.assertEqual(42, result.location.start_column)
        self.assertEqual(49, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
