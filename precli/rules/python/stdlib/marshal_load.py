# Copyright 2024 Secure Saurce LLC
r"""
=======================================================
Deserialization of Untrusted Data in the Marshal Module
=======================================================

The Python ``marshal`` module provides a way to serialize and deserialize
Python objects. However, it is important to be aware that malicious data
can be used to attack applications that use the marshal module. For example,
a malicious data could be used to cause the decoder to execute arbitrary code.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 10

    import marshal


    data = {'name': 'John Doe', 'age': 30}

    with open('data.dat', 'wb') as f:
        marshal.dump(data, f)

    with open('data.dat', 'rb') as f:
        loaded_data = marshal.load(f)

-----------
Remediation
-----------

To avoid this vulnerability, it is important to only deserialize data from
trusted sources. If you are deserializing data from an untrusted source,
you should first sanitize the data to remove any potential malicious code.

.. seealso::

 - `marshal — Internal Python object serialization <https://docs.python.org/3/library/marshal.html>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class MarshalLoad(Rule):
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
                "marshal.*": [
                    "load",
                    "loads",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["marshal.load", "marshal.loads"]:
            """
            marshal.load(file, /)

            marshal.loads(bytes, /)
            """
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
