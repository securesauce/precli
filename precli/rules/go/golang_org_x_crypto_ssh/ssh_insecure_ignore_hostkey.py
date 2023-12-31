# Copyright 2023 Secure Saurce LLC
r"""
=====================================
Improper Hostkey Validation Using SSH
=====================================

The ``golang.org_x_crypto_ssh`` package includes a number of standard methods
for accessing SSH servers. A client should always verify the host key of the
SSH server in order to avoid a number of security risks including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

In the case of a host key that is unknown to the client, the host key callback
should reject the key to cancel the connection.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 14

    package main

    import (
        "fmt"
        "golang.org/x/crypto/ssh"
    )

    func main() {
        config := &ssh.ClientConfig{
            User: "username",
            Auth: []ssh.AuthMethod{
                ssh.Password("password"),
            },
            HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        }

        serverAddress := "example.com:22"

        conn, err := ssh.Dial("tcp", serverAddress, config)
        if err != nil {
            fmt.Println("Failed to dial:", err)
            return
        }
        defer conn.Close()

        session, err := conn.NewSession()
        if err != nil {
            fmt.Println("Failed to create session:", err)
            return
        }
        defer session.Close()

        output, err := session.CombinedOutput("ls -l")
        if err != nil {
            fmt.Println("Failed to execute command:", err)
            return
        }
    }

-----------
Remediation
-----------

Implement a HostKeyCallback fucntion in order to reject connection if the
host key is unknown to the client.

.. code-block:: python
   :linenos:
   :emphasize-lines: 9-22, 29

    package main

    import (
        "fmt"
        "golang.org/x/crypto/ssh"
    )

    func main() {
        hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
            // Here, we hardcode the known host key (for example purposes)
            // In a real-world application, you should replace this with your
            // actual host key
            knownHostPublicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..."))
            if err != nil {
                return err
            }

            if ssh.KeysEqual(knownHostPublicKey, key) {
                return nil // host key matches
            }
            return fmt.Errorf("unknown host key for %s", hostname)
        }

        config := &ssh.ClientConfig{
            User: "username",
            Auth: []ssh.AuthMethod{
                ssh.Password("password"),
            },
            HostKeyCallback: hostKeyCallback,
        }

        serverAddress := "example.com:22"

        conn, err := ssh.Dial("tcp", serverAddress, config)
        if err != nil {
            fmt.Println("Failed to dial:", err)
            return
        }
        defer conn.Close()

        session, err := conn.NewSession()
        if err != nil {
            fmt.Println("Failed to create session:", err)
            return
        }
        defer session.Close()

        output, err := session.CombinedOutput("ls -l")
        if err != nil {
            fmt.Println("Failed to execute command:", err)
            return
        }
    }

.. seealso::

 - `Improper Hostkey Validation Using SSH <https://docs.securesauce.dev/rules/GO501>`_
 - `ssh package - golang.org_x_crypto_ssh - Go Packages <https://pkg.go.dev/golang.org/x/crypto/ssh#InsecureIgnoreHostKey>`_
 - `CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SshInsecureIgnoreHostKey(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="'{}' will bypass host key verification and make the "
            "client vulnerable to man-in-the-middle attacks.",
            targets=("call"),
            wildcards={},
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if (
            call.name_qualified
            == "golang.org/x/crypto/ssh.InsecureIgnoreHostKey"
        ):
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                level=Level.ERROR,
                message=self.message.format("InsecureIgnoreHostKey"),
            )
