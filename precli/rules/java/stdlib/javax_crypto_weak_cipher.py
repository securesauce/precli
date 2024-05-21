# Copyright 2024 Secure Sauce LLC
r"""
# Use of a Broken or Risky Cryptographic Algorithm in `javax.crypto` Package

Using weak ciphers for cryptographic algorithms can pose significant security
risks, and it's generally advised to avoid them in favor of stronger, more
secure algorithms. Here's some guidance that advises against using weak
ciphers like 3DES, Blowfish, DES, RC2, RC4, and RC5:

1. **NIST Recommendations**: The National Institute of Standards and
Technology (NIST) is a widely recognized authority on cryptographic standards.
NIST advises against using weak ciphers in their Special Publication
800-175B: "Guide to Secure Web Services." They recommend the use of stronger
ciphers like AES (Advanced Encryption Standard) and SHA-256 for cryptographic
purposes.

2. **IETF Standards**: The Internet Engineering Task Force (IETF) publishes
standards and guidelines for secure network communication. IETF has deprecated
or discouraged the use of weak ciphers in various RFCs (Request for
Comments). For example, RFC 7465 advises against using SSLv3 and RC4 due to
their vulnerabilities.

3. **OWASP Guidelines**: The Open Web Application Security Project (OWASP)
provides guidelines for secure web applications. Their guidance explicitly
recommends avoiding weak ciphers, including 3DES, Blowfish, DES, RC2, RC4, and
RC5 due to known security weaknesses.

4. **PCI DSS Compliance**: The Payment Card Industry Data Security Standard
(PCI DSS) mandates the use of strong cryptographic algorithms. Using weak
ciphers is discouraged and can lead to non-compliance with PCI DSS
requirements.

5. **Industry Best Practices**: Various cybersecurity experts and
organizations, such as SANS Institute, CERT/CC (Computer Emergency Response
Team Coordination Center), and security vendors, provide guidance on best
practices for cryptographic algorithms. These resources typically recommend
avoiding the use of weak ciphers.

6. **Security Research**: Academic papers and security research often
highlight the vulnerabilities of weak ciphers like 3DES, Blowfish, DES, RC2,
RC4, and RC5. These findings reinforce the importance of avoiding these
ciphers in security-critical applications.

7. **Compliance Standards**: Depending on your industry and location,
there may be specific regulatory requirements that prohibit the use of
weak ciphers. Ensure compliance with applicable regulations by using strong,
approved cryptographic algorithms.

8. **TLS/SSL Configuration**: If you are configuring web servers or other
network services that use TLS/SSL for encryption, it's essential to configure
your server to support only strong ciphersuites and protocols. Weak ciphers,
such as RC4, have known vulnerabilities and should be disabled.

In summary, there is a consensus among reputable standards organizations,
industry experts, and security professionals that weak ciphers like 3DES,
Blowfish, DES, RC2, RC4, and RC5 should be avoided due to their known
vulnerabilities and weaknesses. Instead, it is advisable to use stronger,
more secure cryptographic algorithms and adhere to industry best practices
and regulatory requirements for encryption and security.

## Example

```java
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;


public class Example {
    public static void main(String [] args) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("DES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        } catch (NoSuchPaddingException exception) {
            exception.printStackTrace();
        }
    }
}
```

## Remediation

It is advisable to use stronger, more secure cryptographic algorithms such as
AES.

```java
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;


public class Example {
    public static void main(String [] args) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/NoPadding");
        } catch (NoSuchAlgorithmException exception) {
            exception.printStackTrace();
        } catch (NoSuchPaddingException exception) {
            exception.printStackTrace();
        }
    }
}
```

## See also

- [Cipher (Java SE & JDK)](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html#getInstance(java.lang.String))
- [Java Security Standard Algorithm Names](https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#cipher-algorithms)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)

_New in version 0.5.0_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


WEAK_CIPHERS = ("ARCFOUR", "Blowfish", "DES", "DESede", "RC2", "RC4", "RC5")


class WeakCipher(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="use_of_a_broken_or_risky_cryptographic_algorithm",
            description=__doc__,
            cwe_id=327,
            message="Weak ciphers like '{0}' should be avoided due to their "
            "known vulnerabilities and weaknesses.",
            wildcards={
                "javax.crypto.*": [
                    "Cipher",
                ],
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_method_invocation(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in [
            "javax.crypto.Cipher.getInstance",
        ]:
            return

        argument = call.get_argument(position=0)
        transformation = argument.value_str
        if transformation is None:
            return

        # DES/CBC/PKCS5Padding
        cipher, *mode_padding = transformation.split("/")

        if cipher not in WEAK_CIPHERS:
            return

        content = "/".join(["AES"] + mode_padding)
        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=argument.node),
            description="It is advisable to use a stronger, more "
            "secure cryptographic algorithm like AES.",
            inserted_content=f'"{content}"',
        )

        return Result(
            rule_id=self.id,
            location=Location(node=argument.node),
            message=self.message.format(cipher),
            fixes=fixes,
        )
