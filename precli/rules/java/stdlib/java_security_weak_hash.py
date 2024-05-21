# Copyright 2024 Secure Sauce LLC
r"""
# Reversible One Way Hash in `java.security` Package

The Java `MessageDigest` class provides a number of options for algorithms
to hash data. However, some of the hash algorithms are insecure and should
not be used. These insecure hash algorithms include `MD5` and `SHA-1`.

The MD5 hash algorithm is a cryptographic hash function that was designed in
the early 1990s. MD5 is no longer considered secure, and passwords hashed
with MD5 can be easily cracked by attackers.

The SHA-1 hash algorithm is also a cryptographic hash function that was
designed in the early 1990s. SHA-1 is no longer considered secure, and
passwords hashed with SHA-1 can be easily cracked by attackers.

## Example

```java
import java.security.*;

public class MessageDigestMD5 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("MD5 hashing algorithm not available.");
        }
    }
}
```

## Remediation

The recommendation is to swap the insecure hashing method to one of the more
secure alternatives, `SHA-256` or `SHA-512`.

```java
import java.security.*;

public class MessageDigestSHA256 {
    public static void main(String[] args) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-256 hashing algorithm not available.");
        }
    }
}
```

## See also

- [MessageDigest (Java SE & JDK)](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/MessageDigest.html#getInstance(java.lang.String))
- [CWE-328: Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- [NIST Policy on Hash Functions](https://csrc.nist.gov/projects/hash-functions)

_New in version 0.5.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


WEAK_HASHES = ("MD2", "MD5", "SHA", "SHA1", "SHA-1")


class MessageDigestWeakHash(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="reversible_one_way_hash",
            description=__doc__,
            cwe_id=328,
            message="The hash function '{0}' is vulnerable to collision and "
            "pre-image attacks.",
            wildcards={
                "java.security.*": [
                    "MessageDigest",
                ],
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_method_invocation(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in [
            "java.security.MessageDigest.getInstance",
        ]:
            return

        argument = call.get_argument(position=0)
        algorithm = argument.value_str

        if algorithm is None or algorithm.upper() not in WEAK_HASHES:
            return

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=argument.node),
            description="For cryptographic purposes, use a hash length of at "
            "least 256-bits with hashes such as SHA-256.",
            inserted_content='"SHA-256"',
        )
        return Result(
            rule_id=self.id,
            location=Location(node=argument.node),
            message=self.message.format(algorithm),
            fixes=fixes,
        )
