# Copyright 2023 Secure Saurce LLC
r"""
=====================================================
Improper Certificate Validation Using Requests Module
=====================================================

The ``requests`` package includes a number of standard methods for accessing
HTTP servers. The common parameter in these methods is ``verify`` to denote
whether to verify the server's host certificate. If unset, the default value
is True to verify. However, by setting the value to False, the code is
subject to a number of security risks including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import requests


    requests.get("https://localhost", verify=False)

-----------
Remediation
-----------

Setting the value of the verify argument to True or removing the keyword
argument accomplish the same effect of ensuring that certificates are verified.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import requests


    requests.get("https://localhost", verify=True)

.. seealso::

 - `Improper Certificate Validation Using Requests Module <https://docs.securesauce.dev/rules/PY522>`_
 - `Requests HTTP for Humans™ <https://requests.readthedocs.io/en/latest/>`_
 - `CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class NoCertificateVerify(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' function is set to not verify certificates.",
            targets=("call"),
            wildcards={
                "requests.*": [
                    "delete",
                    "get",
                    "head",
                    "options",
                    "patch",
                    "post",
                    "put",
                    "request",
                    "Session",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "requests.delete",
            "requests.get",
            "requests.head",
            "requests.options",
            "requests.patch",
            "requests.post",
            "requests.put",
            "requests.request",
            "requests.Session.delete",
            "requests.Session.get",
            "requests.Session.head",
            "requests.Session.options",
            "requests.Session.patch",
            "requests.Session.post",
            "requests.Session.put",
            "requests.Session.request",
        ]:
            argument = call.get_argument(name="verify")
            verify = argument.value

            if verify is False:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Set the 'verify' argument to 'True' to ensure"
                    " the server's certificate is verified.",
                    inserted_content="True",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
