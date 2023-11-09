# Copyright 2023 Secure Saurce LLC
r"""
====================================================
Deserialization of Untrusted Data in the Dill Module
====================================================

The Python ``dill`` module provides a way to serialize and deserialize Python
objects. However, it is important to be aware that malicious data can be used
to attack applications that use the ``dill`` module. For example, malicious
data could be used to cause the decoder to execute arbitrary code.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    import dill


    pick = dill.dumps({'a': 'b', 'c': 'd'})
    dill.loads(pick)

-----------
Remediation
-----------

To avoid this vulnerability, it is important to only deserialize data from
trusted sources. If you are deserializing data from an untrusted source, you
should first sanitize the data to remove any potential malicious code.

.. seealso::

 - `Deserialization of Untrusted Data in the Dill Module <https://docs.securesauce.dev/rules/PRE0504>`_
 - `dill package documentation <https://dill.readthedocs.io/en/latest/index.html>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class DillLoad(Rule):
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
                "dill.*": [
                    "load",
                    "loads",
                    "Unpickler",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "dill.load",
            "dill.loads",
            "dill.Unpickler",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                message=self.message.format(call.name_qualified),
            )
