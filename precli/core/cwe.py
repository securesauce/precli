# Copyright 2024 Secure Sauce LLC


class Cwe:
    def __init__(self, id: int):
        self._id = id

    @property
    def id(self) -> int:
        """CWE ID."""
        return self._id

    @property
    def name(self) -> str:
        """Name of the CWE."""
        match self._id:
            case 94:
                return (
                    "Improper Control of Generation of Code ('Code Injection')"
                )
            case 208:
                return "Observable Timing Discrepancy"
            case 214:
                return (
                    "Invocation of Process Using Visible Sensitive Information"
                )
            case 295:
                return "Improper Certificate Validation"
            case 319:
                return "Cleartext Transmission of Sensitive Information"
            case 326:
                return "Inadequate Encryption Strength"
            case 327:
                return "Use of a Broken or Risky Cryptographic Algorithm"
            case 328:
                return "Use of Weak Hash"
            case 330:
                return "Use of Insufficiently Random Values"
            case 377:
                return "Insecure Temporary File"
            case 502:
                return "Deserialization of Untrusted Data"
            case 598:
                return "Use of GET Request Method With Sensitive Query Strings"
            case 614:
                return (
                    "Sensitive Cookie in HTTPS Session Without 'Secure' "
                    "Attribute"
                )
            case 703:
                return "Improper Check or Handling of Exceptional Conditions"
            case 1327:
                return "Binding to an Unrestricted IP Address"
            case 1333:
                return "Inefficient Regular Expression Complexity"

        return self._id

    def url(self) -> str:
        """URL of the CWE."""
        return f"https://cwe.mitre.org/data/definitions/{self._id}.html"
