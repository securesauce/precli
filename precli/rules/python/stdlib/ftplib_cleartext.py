# Copyright 2024 Secure Saurce LLC
r"""
====================================================================
Cleartext Transmission of Sensitive Information in the Ftplib Module
====================================================================

The Python module ``ftplib`` provides a number of functions for accessing FTP
servers. However, the module does not provide any security features. This
means that data transmitted over the network, including passwords, is sent
in cleartext. This makes it possible for attackers to intercept and read
this data.

The Python module ftplib should not be used for accessing FTP servers that
contain sensitive data. There are a number of alternatives to ftplib that
provide security features. These alternatives should be used instead of
ftplib for accessing sensitive data.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import ftplib


    ftp = ftplib.FTP("ftp.us.debian.org")
    ftp.login("user", "password")

    ftp.cwd("debian")
    ftp.retrlines("LIST")

    ftp.quit()

-----------
Remediation
-----------

If the FTP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using ``FTP_TLS`` class. It's also
important to call ``prot_p()`` to secure the data connection.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4,6

    import ftplib


    ftp = ftplib.FTP_TLS("ftp.us.debian.org")
    ftp.login("user", "password")
    ftp.prot_p()

    ftp.cwd("debian")
    ftp.retrlines("LIST")

    ftp.quit()

----------------------
Alternatives to ftplib
----------------------

There are a number of alternatives to ftplib that provide security features.
These alternatives include:

 - ``Paramiko``: Paramiko is a Python module that provides secure access to
   SSH and SFTP servers. Paramiko uses encryption to protect data
   transmitted over the network.

 - ``Twisted``: Twisted is a Python framework that provides a number of
   network protocols, including SSH. Twisted can be used to create secure
   SFTP clients and servers.

.. seealso::

 - `ftplib — FTP protocol client <https://docs.python.org/3/library/ftplib.html>`_
 - `CWE-319: Cleartext Transmission of Sensitive Information <https://cwe.mitre.org/data/definitions/319.html>`_
 - https://www.paramiko.org/
 - https://twisted.org/

.. versionadded::  0.1.0

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class FtpCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The FTP protocol can transmit data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "ftplib.*": [
                    "FTP",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["ftplib.FTP"]:
            """
            FTP(
                host='',
                user='',
                passwd='',
                acct='',
                timeout=<object object at 0x104730630>,
                source_address=None,
                *,
                encoding='utf-8'
            )

            FTP_TLS(
                host='',
                user='',
                passwd='',
                acct='',
                keyfile=None,
                certfile=None,
                context=None,
                timeout=<object object at 0x104730630>,
                source_address=None,
                *,
                encoding='utf-8'
            )
            """
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.identifier_node),
                description="Use the 'FTP_TLS' module to secure the "
                "connection.",
                inserted_content="FTP_TLS",
            )

            # TODO(ericwb): Default of FTP_TLS context=None creates unsecure
            # _create_unverified_context. Therefore need to suggest
            # create_default_context as part of fix.

            # TODO(ericwb): the fix should also call prot_p() to secure the
            # data connection

            if call.get_argument(position=2, name="passwd").value is not None:
                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.function_node),
                    level=Level.ERROR,
                    message=f"The '{call.name_qualified}' module will "
                    f"transmit the password argument in cleartext.",
                    fixes=fixes,
                )
            else:
                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.function_node),
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
        if call.name_qualified in ["ftplib.FTP.login"]:
            """
            login(self, user='', passwd='', acct='')
            """
            if call.get_argument(position=1, name="passwd").value is not None:
                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.identifier_node),
                    level=Level.ERROR,
                    message=f"The '{call.name_qualified}' function will "
                    f"transmit the password argument in cleartext.",
                )
