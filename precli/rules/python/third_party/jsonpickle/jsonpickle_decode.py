# Copyright 2023 Secure Saurce LLC
r"""
======================================================
Deserialization of Untrusted Data in JsonPickle Module
======================================================

The Python ``jsonpickle`` module is a serialization module that can be used
to serialize and deserialize Python objects to and from JSON. Pickle is not
secure because it can be used to deserialize malicious code. For example,
an attacker could create a pickle file that contains malicious code and then
trick a user into opening the file. When the user opens the file, the
malicious code would be executed.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import jsonpickle


    pick = jsonpickle.encode({'a': 'b', 'c': 'd'})
    jsonpickle.decode(pick)

-----------
Remediation
-----------

Consider signing data with hmac if you need to ensure that pickle data has
not been tampered with.

.. seealso::

 - `Deserialization of Untrusted Data in JsonPickle Module <https://docs.securesauce.dev/rules/PRE0507>`_
 - `jsonpickle Documentation <https://jsonpickle.github.io/>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_
 - `pickle — Python object serialization <https://docs.python.org/3/library/pickle.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class JsonpickleDecode(Rule):
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
                "jsonpickle.*": [
                    "decode",
                ],
                "jsonpickle.unpickler.*": [
                    "decode",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "jsonpickle.decode",
            "jsonpickle.unpickler.decode",
            "jsonpickle.unpickler.Unpickler",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                message=self.message.format(call.name_qualified),
            )
