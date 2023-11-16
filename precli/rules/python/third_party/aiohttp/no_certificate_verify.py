# Copyright 2023 Secure Saurce LLC
r"""
====================================================
Improper Certificate Validation Using Aiohttp Module
====================================================

The ``aiohttp`` package includes a number of asynchronous methods for accessing
HTTP servers. The common parameter in these methods is ``ssl`` to denote
whether to verify the server's host certificate. If unset, the default value
is to verify certificates. However, by setting the value to False, the code is
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

    import aiohttp


    async with aiohttp.ClientSession() as session:
        async with session.get('http://python.org', ssl=False) as response:
            print(await response.text())

-----------
Remediation
-----------

Setting the value of the ssl argument to None or removing the keyword
argument accomplish the same effect of ensuring that certificates are verified.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import aiohttp


    async with aiohttp.ClientSession() as session:
        async with session.get('http://python.org', ssl=None) as response:
            print(await response.text())

.. seealso::

 - `Improper Certificate Validation Using Requests Module <https://docs.securesauce.dev/rules/PRE0501>`_
 - `Advanced Client Usage — aiohttp documentation <https://docs.aiohttp.org/en/stable/client_advanced.html#ssl-control-for-tcp-sockets>`_
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
                "aiohttp.ClientSession.*": [
                    "delete",
                    "get",
                    "head",
                    "options",
                    "patch",
                    "post",
                    "put",
                    "request",
                    "ws_connect",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "aiohttp.ClientSession.delete",
            "aiohttp.ClientSession.get",
            "aiohttp.ClientSession.head",
            "aiohttp.ClientSession.options",
            "aiohttp.ClientSession.patch",
            "aiohttp.ClientSession.post",
            "aiohttp.ClientSession.put",
            "aiohttp.ClientSession.request",
            "aiohttp.ClientSession.ws_connect",
        ]:
            argument = call.get_argument(name="ssl")
            ssl = argument.value
            if ssl is None:
                argument = call.get_argument(name="verify_ssl")
                ssl = argument.value

            if ssl is False:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Set the 'ssl' argument to 'None' to ensure"
                    " the server's certificate is verified.",
                    inserted_content="None",
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
