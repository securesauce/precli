# Copyright 2024 Secure Saurce LLC
r"""
======================================================
Deserialization of Untrusted Data in the Shelve Module
======================================================

The Python ``shelve`` module provides a way to store Python objects in a file.
It is backed by the pickle module, which is a serialization format that can
be used to store arbitrary Python objects.

However, it is important to be aware that the shelve module is not secure
against malicious data. For example, a malicious shelf could be used to
cause the decoder to execute arbitrary code.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import shelve


    with shelve.open('spam') as db:
        db['eggs'] = 'eggs'

-----------
Remediation
-----------

To avoid this vulnerability, it is important to only use the shelve module
with data from trusted sources. If you are using the shelve module with
data from an untrusted source, you should first sanitize the data to remove
any potential malicious code.

.. seealso::

 - `shelve — Python object persistence <https://docs.python.org/3/library/shelve.html>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ShelveOpen(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe_id=502,
            message="Potential unsafe usage of '{}' that can allow "
            "instantiation of arbitrary objects.",
            targets=("call"),
            wildcards={
                "shelve.*": [
                    "open",
                    "DbfilenameShelf",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["shelve.open", "shelve.DbfilenameShelf"]:
            return Result(
                rule_id=self.id,
                artifact=context["artifact"],
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
