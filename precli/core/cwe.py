# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
from precli.i18n import _


class Cwe:
    _cwe_names = {
        22: _(
            "Improper Limitation of a Pathname to a Restricted Directory "
            "('Path Traversal')"
        ),
        78: _(
            "Improper Neutralization of Special Elements used in an OS "
            "Command ('OS Command Injection')"
        ),
        79: _(
            "Improper Neutralization of Input During Web Page Generation "
            "('Cross-site Scripting')"
        ),
        94: _("Improper Control of Generation of Code ('Code Injection')"),
        95: _(
            "Improper Neutralization of Directives in Dynamically Evaluated "
            "Code ('Eval Injection')"
        ),
        208: _("Observable Timing Discrepancy"),
        214: _("Invocation of Process Using Visible Sensitive Information"),
        215: _("Insertion of Sensitive Information Into Debugging Code"),
        250: _("Execution with Unnecessary Privileges"),
        295: _("Improper Certificate Validation"),
        319: _("Cleartext Transmission of Sensitive Information"),
        326: _("Inadequate Encryption Strength"),
        306: _("Missing Authentication for Critical Function"),
        327: _("Use of a Broken or Risky Cryptographic Algorithm"),
        328: _("Use of Weak Hash"),
        330: _("Use of Insufficiently Random Values"),
        338: _(
            "Use of Cryptographically Weak Pseudo-Random Number Generator "
            "(PRNG)"
        ),
        347: _("Improper Verification of Cryptographic Signature"),
        377: _("Insecure Temporary File"),
        502: _("Deserialization of Untrusted Data"),
        598: _("Use of GET Request Method With Sensitive Query Strings"),
        614: _("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"),
        676: _("Use of Potentially Dangerous Function"),
        693: _("Protection Mechanism Failure"),
        703: _("Improper Check or Handling of Exceptional Conditions"),
        732: _("Incorrect Permission Assignment for Critical Resource"),
        770: _("Allocation of Resources Without Limits or Throttling"),
        942: _("Permissive Cross-domain Policy with Untrusted Domains"),
        1088: _("Synchronous Access of Remote Resource without Timeout"),
        1327: _("Binding to an Unrestricted IP Address"),
        1333: _("Inefficient Regular Expression Complexity"),
    }

    def __init__(self, id: int):
        self._id = id

    @property
    def id(self) -> int:
        """CWE ID."""
        return self._id

    @property
    def name(self) -> str:
        """Name of the CWE."""
        return self._cwe_names.get(self._id, str(self._id))

    @property
    def url(self) -> str:
        """URL of the CWE."""
        return f"https://cwe.mitre.org/data/definitions/{self._id}.html"
