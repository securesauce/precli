# Copyright 2024 Secure Saurce LLC
r"""
====================================================================
Cleartext Transmission of Sensitive Information in the Poplib Module
====================================================================

The Python module ``poplib`` provides a number of functions for accessing
POP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module poplib should only in a secure mannner to protect sensitive
data when accessing POP servers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import getpass
    import poplib


    M = poplib.POP3('localhost')
    M.user(getpass.getuser())
    M.pass_(getpass.getpass())
    numMessages = len(M.list()[1])
    for i in range(numMessages):
        for j in M.retr(i+1)[1]:
            print(j)

-----------
Remediation
-----------

If the POP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using ``POP3_SSL`` class.
Alternatively, the ``stls`` function can be used to enter a secure session.

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import getpass
    import poplib


    M = poplib.POP3_SSL('localhost')
    M.user(getpass.getuser())
    M.pass_(getpass.getpass())
    numMessages = len(M.list()[1])
    for i in range(numMessages):
        for j in M.retr(i+1)[1]:
            print(j)

.. seealso::

 - `poplib — POP3 protocol client <https://docs.python.org/3/library/poplib.html>`_
 - `CWE-319: Cleartext Transmission of Sensitive Information <https://cwe.mitre.org/data/definitions/319.html>`_

.. versionadded:: 0.1.9

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PopCleartext(Rule):
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
                "poplib.*": [
                    "POP3",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "poplib.POP3.user",
            "poplib.POP3.pass_",
            "poplib.POP3.apop",
            "poplib.POP3.rpop",
        ]:
            symbol = context["symtab"].get(call.var_node.text.decode())

            if "stls" not in [
                x.identifier_node.text.decode() for x in symbol.call_history
            ]:
                init_call = symbol.call_history[0]
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=init_call.identifier_node),
                    description="Use the 'POP3_SSL' module to secure the "
                    "connection.",
                    inserted_content="POP3_SSL",
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
