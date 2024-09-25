# Copyright 2024 Secure Sauce LLC


class Cwe:
    _cwe_names = {
        79: (
            "Improper Neutralization of Input During Web Page Generation "
            "('Cross-site Scripting')"
        ),
        94: "Improper Control of Generation of Code ('Code Injection')",
        208: "Observable Timing Discrepancy",
        214: "Invocation of Process Using Visible Sensitive Information",
        215: "Insertion of Sensitive Information Into Debugging Code",
        250: "Execution with Unnecessary Privileges",
        295: "Improper Certificate Validation",
        319: "Cleartext Transmission of Sensitive Information",
        326: "Inadequate Encryption Strength",
        306: "Missing Authentication for Critical Function",
        327: "Use of a Broken or Risky Cryptographic Algorithm",
        328: "Use of Weak Hash",
        330: "Use of Insufficiently Random Values",
        338: (
            "Use of Cryptographically Weak Pseudo-Random Number Generator "
            "(PRNG)"
        ),
        347: "Improper Verification of Cryptographic Signature",
        377: "Insecure Temporary File",
        502: "Deserialization of Untrusted Data",
        598: "Use of GET Request Method With Sensitive Query Strings",
        614: "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        703: "Improper Check or Handling of Exceptional Conditions",
        732: "Incorrect Permission Assignment for Critical Resource",
        1088: "Synchronous Access of Remote Resource without Timeout",
        1327: "Binding to an Unrestricted IP Address",
        1333: "Inefficient Regular Expression Complexity",
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
