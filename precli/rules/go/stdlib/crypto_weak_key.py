# Copyright 2024 Secure Sauce LLC
r"""
# Inadequate Encryption Strength Using Weak Keys in `crypto` Package

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

## Example

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "log"
)

func main() {
    privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }
}
```

## Remediation

Its recommended to increase the key size to at least 2048 for DSA and RSA
algorithms.

```go
package main

import (
    "crypto/rand"
    "crypto/rsa"
    "log"
)

func main() {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }
}
```

## See also

- [dsa package - crypto_dsa - Go Packages](https://pkg.go.dev/crypto/dsa#ParameterSizes)
- [rsa package - crypto_rsa - Go Packages](https://pkg.go.dev/crypto/rsa#GenerateKey)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)

_New in version 0.2.1_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class WeakKey(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            description=__doc__,
            cwe_id=326,
            message="Using '{0}' key sizes less than '{1}' bits is considered "
            "vulnerable to attacks.",
            wildcards={},
        )

    def analyze_call_expression(self, context: dict, call: Call) -> Result:
        if call.name_qualified in ["crypto/dsa.GenerateParameters"]:
            argument = call.get_argument(position=2)
            sizes = argument.value

            if sizes == "crypto/dsa.L1024N160":
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use a minimum key size of 2048 for DSA keys.",
                    inserted_content="L2048N224",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.identifier_node),
                    level=Level.ERROR,
                    message=self.message.format("DSA", 2048),
                    fixes=fixes,
                )
        elif call.name_qualified in ["crypto/rsa.GenerateKey"]:
            argument = call.get_argument(position=1)
            bits = argument.value

            if isinstance(bits, int) and bits < 2048:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Use a minimum key size of 2048 for RSA keys.",
                    inserted_content="2048",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.node),
                    level=Level.ERROR if bits <= 1024 else Level.WARNING,
                    message=self.message.format("RSA", 2048),
                    fixes=fixes,
                )
