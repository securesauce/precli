# Copyright 2024 Secure Saurce LLC
r"""
=====================================================================
Cleartext Transmission of Sensitive Information in the Smtplib Module
=====================================================================

The Python module ``smtplib`` provides a number of functions for accessing
SMTP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module smtplib should only in a secure mannner to protect sensitive
data when accessing SMTP servers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 24

    import smtplib


    def prompt(prompt):
        return input(prompt).strip()

    fromaddr = prompt("From: ")
    toaddrs  = prompt("To: ").split()
    print("Enter message, end with ^D (Unix) or ^Z (Windows):")

    # Add the From: and To: headers at the start!
    msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, ", ".join(toaddrs)))
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line:
            break
        msg = msg + line

    print("Message length is", len(msg))

    server = smtplib.SMTP('localhost')
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()

-----------
Remediation
-----------

If the SMTP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using ``SMTP_SSL`` class.
Alternatively, the ``starttls`` function can be used to enter a secure session.


.. code-block:: python
   :linenos:
   :emphasize-lines: 24

    import smtplib


    def prompt(prompt):
        return input(prompt).strip()

    fromaddr = prompt("From: ")
    toaddrs  = prompt("To: ").split()
    print("Enter message, end with ^D (Unix) or ^Z (Windows):")

    # Add the From: and To: headers at the start!
    msg = ("From: %s\r\nTo: %s\r\n\r\n" % (fromaddr, ", ".join(toaddrs)))
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line:
            break
        msg = msg + line

    print("Message length is", len(msg))

    server = smtplib.SMTP_SSL('localhost')
    server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()

.. seealso::

 - `smtplib — SMTP protocol client <https://docs.python.org/3/library/smtplib.html>`_
 - `CWE-319: Cleartext Transmission of Sensitive Information <https://cwe.mitre.org/data/definitions/319.html>`_

.. versionadded:: 0.1.9

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class SmtpCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The POP protocol can transmit data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "smtplib.*": [
                    "SMTP",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "smtplib.SMTP.login",
            "smtplib.SMTP.auth",
        ]:
            symbol = context["symtab"].get(call.var_node.text.decode())

            if "starttls" not in [
                x.identifier_node.text.decode() for x in symbol.call_history
            ]:
                init_call = symbol.call_history[0]
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=init_call.identifier_node),
                    description="Use the 'SMTP_SSL' module to secure the "
                    "connection.",
                    inserted_content="SMTP_SSL",
                )

                return Result(
                    rule_id=self.id,
                    artifact=context["artifact"],
                    location=Location(node=call.identifier_node),
                    level=Level.ERROR,
                    message=f"The '{call.name_qualified}' function will "
                    f"transmit authentication information such as a user, "
                    "password in cleartext.",
                    fixes=fixes,
                )
