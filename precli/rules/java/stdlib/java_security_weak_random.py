# Copyright 2024 Secure Sauce LLC
r"""
# Use of Cryptographically Weak Pseudo-Random Number Generator `SHA1PRNG`

This rule identifies instances where the Java SecureRandom class is
instantiated with the SHA1PRNG algorithm. While SHA1PRNG has been widely
used, it is considered less secure and potentially vulnerable compared to
newer algorithms available. The use of stronger algorithms is recommended
to ensure the cryptographic strength of random numbers.

The `SHA1PRNG` algorithm for SecureRandom may not provide a sufficiently strong
level of randomness for security-sensitive applications. `SHA-1` has been
found to be weaker against collision attacks, and while `SHA1PRNG` is not
directly equivalent to `SHA-1`, its association and the lack of transparency
in its implementation across different Java platforms raise concerns about
its suitability and security. Modern cryptographic applications require
stronger guarantees of randomness to prevent attacks.

# Example

```java linenums="1" hl_lines="6" title="SecureRandomSHA1PRNG.java"
import java.security.*;

public class WeakRNG {
    public static void main(String[] args) {
        try {
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA1PRNG random algorithm not available.");
        }
    }
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/java/stdlib/java_security/examples/SecureRandomSHA1PRNG.java
    ⚠️  Warning on line 6 in tests/unit/rules/java/stdlib/java_security/examples/SecureRandomSHA1PRNG.java
    JAV004: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
    The SecureRandom algorithm 'SHA1PRNG' may not provide sufficient entropy.
    ```

# Remediation

It is recommended to use SecureRandom without specifying an algorithm,
allowing the Java runtime to select the strongest available algorithm, or
explicitly specify a more secure algorithm like `NativePRNG` or `DRBG` where
available and appropriate for the application's requirements. This ensures
the use of secure and up-to-date algorithms for random number generation.

```java linenums="1" hl_lines="5" title="SecureRandomSHA1PRNG.java"
import java.security.*;

public class StrongRNG {
    public static void main(String[] args) {
        SecureRandom sr = new SecureRandom();
    }
}
```

# See also

!!! info
    - [SecureRandom (Java SE & JDK)](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/SecureRandom.html#getInstance(java.lang.String))
    - [CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html)
    - [Recommendations for Random Number Generation Using Deterministic Random Bit Generators (NIST SP 800-90A)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)
    - [Weak Random](https://thesecurityvault.com/weak-random/)
    - [Android Developers Blog Security Crypto provider deprecated in Android N](https://android-developers.googleblog.com/2016/06/security-crypto-provider-deprecated-in.html)

_New in version 0.5.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SecureRandomWeakRandom(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="weak_prng",
            description=__doc__,
            cwe_id=338,
            message="The SecureRandom algorithm '{0}' may not provide "
            "sufficient entropy.",
            wildcards={
                "java.security.*": [
                    "SecureRandom",
                ],
            },
        )

    def analyze_method_invocation(
        self, context: dict, call: Call
    ) -> Result | None:
        if call.name_qualified not in [
            "java.security.SecureRandom.getInstance",
        ]:
            return

        argument = call.get_argument(position=0)
        algorithm = argument.value_str

        if algorithm is None or algorithm.upper() != "SHA1PRNG":
            return

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=argument.node),
            description="Use SecureRandom without specifying an algorithm, "
            "allowing the Java runtime to select the strongest available "
            "algorithm.",
            inserted_content='"DRBG"',
        )
        return Result(
            rule_id=self.id,
            location=Location(node=argument.node),
            message=self.message.format(algorithm),
            fixes=fixes,
        )
