# Copyright 2024 Secure Saurce LLC
r"""
=====================================================================
Cleartext Transmission of Sensitive Information in the Nntplib Module
=====================================================================

The Python module ``nntplib`` provides a number of functions for accessing
NNTP servers. However, the default behavior of the module does not provide
utilize secure connections. This means that data transmitted over the network,
including passwords, is sent in cleartext. This makes it possible for attackers
to intercept and read this data.

The Python module nntplib should only in a secure mannner to protect sensitive
data when accessing NNTP servers.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from nntplib import NNTP


    with NNTP('news.gmane.io') as n:
        n.group('gmane.comp.python.committers')

-----------
Remediation
-----------

If the NNTP protocol must be used and sensitive data will be transferred, it
is recommended to secure the connection using ``NNTP_SSL`` class.
Alternatively, the ``starttls`` function can be used to enter a secure session.


.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    from nntplib import NNTP


    with NNTP_SSL('news.gmane.io') as n:
        n.group('gmane.comp.python.committers')

.. seealso::

 - `nntplib — NNTP protocol client <https://docs.python.org/3/library/nntplib.html>`_
 - `CWE-319: Cleartext Transmission of Sensitive Information <https://cwe.mitre.org/data/definitions/319.html>`_

.. versionadded:: 0.1.9

"""  # noqa: E501
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class NntpCleartext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="cleartext_transmission",
            full_descr=__doc__,
            cwe_id=319,
            message="The NNTP protocol can transmit data in cleartext without "
            "encryption.",
            targets=("call"),
            wildcards={
                "nntplib.*": [
                    "NNTP",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["nntplib.NNTP.login"]:
            symbol = context["symtab"].get(call.var_node.text.decode())

            if "starttls" not in [
                x.identifier_node.text.decode() for x in symbol.call_history
            ]:
                init_call = symbol.call_history[0]
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=init_call.identifier_node),
                    description="Use the 'NNTP_SSL' module to secure the "
                    "connection.",
                    inserted_content="NNTP_SSL",
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
