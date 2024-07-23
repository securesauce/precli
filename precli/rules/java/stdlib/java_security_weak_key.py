# Copyright 2024 Secure Sauce LLC
r"""
# Inadequate Encryption Strength Using Weak Keys in `java.security` Package

Using weak key sizes for cryptographic algorithms like RSA and DSA can
compromise the security of your encryption and digital signatures. Here's a
brief overview of the risks associated with weak key sizes for these
algorithms:

RSA (Rivest-Shamir-Adleman):
RSA is widely used for both encryption and digital signatures. Weak key sizes
in RSA can be vulnerable to factorization attacks, such as the famous RSA-129
challenge, which was factored in 1994 after 17 years of effort. Using small
key sizes makes it easier for attackers to factor the modulus and recover
the private key.

It's generally recommended to use RSA key sizes of 2048 bits or more for
security in the present day, with 3072 bits or higher being increasingly
preferred for long-term security.

DSA (Digital Signature Algorithm):
DSA is used for digital signatures and relies on the discrete logarithm
problem. Using weak key sizes in DSA can make it susceptible to attacks that
involve solving the discrete logarithm problem, like the GNFS (General
Number Field Sieve) algorithm.

For DSA, key sizes of 2048 bits or more are recommended for modern security.
Note that DSA is not as commonly used as RSA or ECC for new applications, and
ECDSA (Elliptic Curve Digital Signature Algorithm) is often preferred due to
its efficiency and strong security properties.

# Example

```java linenums="1" hl_lines="7" title="KeyPairGeneratorRSA.java"
import java.security.*;

public class KeyPairGeneratorRSA {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("RSA algorithm not available.");
        }
    }
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/java/stdlib/java_security/examples/KeyPairGeneratorRSA.java
    ⛔️ Error on line 7 in tests/unit/rules/java/stdlib/java_security/examples/KeyPairGeneratorRSA.java
    JAV003: Inadequate Encryption Strength
    Using 'RSA' key sizes less than '2048' bits is considered vulnerable to attacks.
    ```

# Remediation

Its recommended to increase the key size to at least 2048 for DSA and RSA
algorithms.

```java linenums="1" hl_lines="7" title="KeyPairGeneratorRSA.java"
import java.security.*;

public class KeyPairGeneratorRSA {
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("RSA algorithm not available.");
        }
    }
}
```

# See also

!!! info
    - [KeyPairGenerator (Java SE & JDK)](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/KeyPairGenerator.html)
    - [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

_New in version 0.5.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class KeyPairGeneratorWeakKey(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            description=__doc__,
            cwe_id=326,
            message="Using '{0}' key sizes less than '{1}' bits is considered "
            "vulnerable to attacks.",
            wildcards={
                "java.security.*": [
                    "KeyPairGenerator",
                ],
            },
        )

    def analyze_method_invocation(
        self, context: dict, call: Call
    ) -> Result | None:
        if call.name_qualified not in [
            "java.security.KeyPairGenerator.getInstance.initialize"
        ]:
            return

        argument = call.get_argument(position=0)
        keysize = argument.value

        symbol = context["symtab"].get(call.var_node.text.decode())
        if "getInstance" not in [
            x.identifier_node.text.decode() for x in symbol.call_history
        ]:
            return

        get_instance_call = symbol.call_history[0]
        algorithm = get_instance_call.get_argument(position=0).value_str
        if algorithm is None or algorithm.upper() not in ("DSA", "RSA"):
            return

        if isinstance(keysize, int) and keysize < 2048:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=argument.node),
                description="Use a minimum key size of 2048 for RSA keys.",
                inserted_content="2048",
            )

            return Result(
                rule_id=self.id,
                location=Location(node=argument.node),
                level=Level.ERROR if keysize <= 1024 else Level.WARNING,
                message=self.message.format("RSA", 2048),
                fixes=fixes,
            )
