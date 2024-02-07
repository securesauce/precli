# Copyright 2024 Secure Saurce LLC
r"""
==================================================================
Use of a Broken or Risky Cryptographic Algorithm in Crypto Package
==================================================================

Using weak ciphers for cryptographic algorithms can pose significant security
risks, and it's generally advised to avoid them in favor of stronger, more
secure algorithms. Here's some guidance that advises against using weak
ciphers like DES and RC4:

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
recommends avoiding weak ciphers, including DES and RC4 due to known security
weaknesses.

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
highlight the vulnerabilities of weak ciphers like DES and RC4. These
findings reinforce the importance of avoiding these ciphers in
security-critical applications.

7. **Compliance Standards**: Depending on your industry and location,
there may be specific regulatory requirements that prohibit the use of
weak ciphers. Ensure compliance with applicable regulations by using strong,
approved cryptographic algorithms.

8. **TLS/SSL Configuration**: If you are configuring web servers or other
network services that use TLS/SSL for encryption, it's essential to configure
your server to support only strong ciphersuites and protocols. Weak ciphers,
such as RC4, have known vulnerabilities and should be disabled.

In summary, there is a consensus among reputable standards organizations,
industry experts, and security professionals that weak ciphers like DES and
RC4 should be avoided due to their known vulnerabilities and weaknesses.
Instead, it is advisable to use stronger, more secure cryptographic algorithms
and adhere to industry best practices and regulatory requirements for
encryption and security.

-------
Example
-------

.. code-block:: go
   :linenos:
   :emphasize-lines: 14

    package main

    import (
        "crypto/des"
    )

    func main() {
        ede2Key := []byte("example key 1234")

        var tripleDESKey []byte
        tripleDESKey = append(tripleDESKey, ede2Key[:16]...)
        tripleDESKey = append(tripleDESKey, ede2Key[:8]...)

        _, err := des.NewTripleDESCipher(tripleDESKey)
        if err != nil {
            panic(err)
        }
    }

-----------
Remediation
-----------

It is advisable to use stronger, more secure cryptographic algorithms such as
AES.

.. code-block:: go
   :linenos:
   :emphasize-lines: 4,10

    package main

    import (
        "crypto/aes"
    )

    func main() {
        aesKey := []byte("example key 1234")

        _, err := aes.NewCipher(aesKey)
        if err != nil {
            panic(err)
        }
    }

.. seealso::

 - `des package - crypto_des - Go Packages <https://pkg.go.dev/crypto/des>`_
 - `rc4 package - crypto_rc4 - Go Packages <https://pkg.go.dev/crypto/rc4>`_
 - `CWE-327: Use of a Broken or Risky Cryptographic Algorithm <https://cwe.mitre.org/data/definitions/327.html>`_

.. versionadded:: 0.2.1

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class WeakCipher(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="use_of_a_broken_or_risky_cryptographic_algorithm",
            full_descr=__doc__,
            cwe_id=327,
            message="Weak ciphers like {} should be avoided due to their "
            "known vulnerabilities and weaknesses.",
            targets=("call"),
            wildcards={},
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "crypto/des.NewCipher",
            "crypto/des.NewTripleDESCipher",
            "crypto/rc4.NewCipher",
        ]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.function_node),
                description="It is advisable to use a stronger, more "
                "secure cryptographic algorithm like AES.",
                inserted_content="aes.NewCipher",
            )
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                level=Level.ERROR,
                message=self.message.format(call.name),
                fixes=fixes,
            )
