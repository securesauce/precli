# Copyright 2023 Secure Saurce LLC
r"""
====================================================================
Cleartext Transmission of Sensitive Information in the Pyghmi Module
====================================================================

The Python module ``pyghmi`` provides a number of functions for accessing IPMI
servers. IPMI is a protocol for accessing and administrating servers at the
hardware level. IPMI runs on the Baseboard Management Controller (BMC) and
provides access to the BIOS, disks, and other hardware.

However, the protocol and thus the Python module does not provide adequate
security features. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for
attackers to intercept and read this data.

The Python module ``pyghmi`` should not be used for accessing IPMI servers
on an untrusted network.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4,5,6

    from pyghmi.ipmi import command


    cmd = command.Command(bmc="bmc",
                          userid="userid",
                          password="ZjE4ZjI0NTE4YmI2NGJjZDliOGY3ZmJiY2UyN2IzODQK")

-----------
Remediation
-----------

If the IPMI protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using SSH tunneling. If available,
SSH transport networking data over an encrypted connection.

Otherwise, it is very important to keep communication with IPMI over a private
secure network.

.. code-block:: python
   :linenos:

    import paramiko


    # IPMI device information
    ipmi_port = 623
    ipmi_username = 'your_ipmi_username'
    ipmi_password = 'your_ipmi_password'

    # SSH server information
    ssh_host = 'ssh.example.com'
    ssh_port = 22
    ssh_username = 'your_ssh_username'
    ssh_password = 'your_ssh_password'

    # Local port to forward the IPMI traffic through
    local_port = 6230

    try:
        # Connect to the SSH server
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
        ssh_client.connect(ssh_host, ssh_port, ssh_username, ssh_password)

        # Set up the SSH tunnel
        transport = ssh_client.get_transport()
        transport.set_keepalive(30)
        transport.request_port_forward('', ipmi_port)

        print('SSH tunnel established. IPMI traffic is being forwarded to localhost')

        # You can now communicate with the IPMI device through the SSH tunnel.
        # For example, you can use an IPMI client or library like 'pyghmi' to interact with the IPMI device using the local_port.

        transport.cancel_port_forward('', local_port)
        ssh_client.close()

    except Exception as e:
        print(f'Error: {e}')

.. seealso::

 - `Cleartext Transmission of Sensitive Information in the Pyghmi Module <https://docs.securesauce.dev/rules/PRE0509>`_
 - `Documentation — pyghmi documentation <https://docs.openstack.org/pyghmi/latest/>`_
 - `CWE-319: Cleartext Transmission of Sensitive Information <https://cwe.mitre.org/data/definitions/319.html>`_
 - `Risks of Using the Intelligent Platform Management Interface (IPMI) CISA <https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PyghmiCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The '{}' module may transmit data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "pyghmi.ipmi.command.*": [
                    "Command",
                    "Console",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "pyghmi.ipmi.command.Command",
            "pyghmi.ipmi.command.Console",
        ]:
            argument = call.get_argument(position=2, name="password")
            passwd = argument.value

            if passwd is not None:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.function_node,
                    ),
                    level=Level.ERROR,
                    message=f"The {call.name_qualified} module may "
                    f"transmit the password argument in cleartext.",
                )
            else:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.function_node,
                    ),
                    message=self.message.format(call.name_qualified),
                )
