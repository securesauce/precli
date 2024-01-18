# Copyright 2023 Secure Saurce LLC
r"""
=====================================================
Improper Certificate Validation Using Paramiko Module
=====================================================

The ``paramiko`` package includes a number of standard methods for accessing
SSH servers. A client should always verify the host key of the SSH server
in order to avoid a number of security risks including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

In the case of a host key that is unknown to the client, the policy should
be set to no longer proceed with the connection.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    from paramiko import client


    ssh_client = client.SSHClient()
    ssh_client.set_missing_host_key_policy(client.AutoAddPolicy)

-----------
Remediation
-----------

Set the missing host key policy to ``RejectPolicy`` in order to reject a
connection if the host key is unknown to the client.

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    from paramiko import client


    ssh_client = client.SSHClient()
    ssh_client.set_missing_host_key_policy(client.RejectPolicy)

.. seealso::

 - `Improper Certificate Validation Using Paramiko Module <https://docs.securesauce.dev/rules/PY512>`_
 - `Paramiko’s documentation <https://docs.paramiko.org/en/latest/>`_
 - `CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ParamikoNoHostKeyVerify(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' missing host key policy will not properly "
            "verify the SSH server's host key.",
            targets=("call"),
            wildcards={
                "paramiko.client.*": [
                    "SSHClient",
                    "AutoAddPolicy",
                    "WarningPolicy",
                ],
                "paramiko.*": [
                    "SSHClient",
                    "AutoAddPolicy",
                    "WarningPolicy",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "paramiko.SSHClient.set_missing_host_key_policy",
            "paramiko.client.SSHClient.set_missing_host_key_policy",
        ]:
            argument = call.get_argument(position=0, name="policy")
            policy = argument.value

            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=argument.identifier_node),
                description="Use 'RejectPolicy' as the 'policy' argument"
                " to safely reject unknown host keys.",
                inserted_content="RejectPolicy",
            )

            if policy in [
                "paramiko.AutoAddPolicy",
                "paramiko.client.AutoAddPolicy",
            ]:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format("AutoAddPolicy"),
                    fixes=fixes,
                )
            if policy in [
                "paramiko.WarningPolicy",
                "paramiko.client.WarningPolicy",
            ]:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.WARNING,
                    message=self.message.format("WarningPolicy"),
                    fixes=fixes,
                )
