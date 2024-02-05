# Copyright 2024 Secure Saurce LLC
r"""
====================================================
Deserialization of Untrusted Data in the Json Module
====================================================

The Python ``json`` module provides a way to parse and generate JSON data.
However, it is important to be aware that malicious JSON strings can be used
to attack applications that use the json module. For example, a malicious
JSON string could be used to cause the decoder to consume considerable CPU
and memory resources, which could lead to a denial-of-service attack.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import json


    json.loads('["foo", {"bar":["baz", null, 1.0, 2]}]')

-----------
Remediation
-----------

To avoid this vulnerability, it is important to only parse JSON data from
trusted sources. If you are parsing JSON data from an untrusted source, you
should first sanitize the data to remove any potential malicious code.

.. seealso::

 - `json — JSON encoder and decoder <https://docs.python.org/3/library/json.html>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class JsonLoad(Rule):
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
                "json.*": [
                    "load",
                    "loads",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "json.load",
            "json.loads",
            "json.JSONDecoder.decode",
        ]:
            """
            json.load(
                fp,
                *,
                cls=None,
                object_hook=None,
                parse_float=None,
                parse_int=None,
                parse_constant=None,
                object_pairs_hook=None,
                **kw
            )
            json.loads(
                s,
                *,
                cls=None,
                object_hook=None,
                parse_float=None,
                parse_int=None,
                parse_constant=None,
                object_pairs_hook=None,
                **kw
            )
            json.JSONDecoder(
                *,
                object_hook=None,
                parse_float=None,
                parse_int=None,
                parse_constant=None,
                strict=True,
                object_pairs_hook=None
            ).decode(
                self,
                s,
                _w=<built-in method match of re.Pattern object at 0x1049ec790>
            )
            """
            return Result(
                rule_id=self.id,
                artifact=context["artifact"],
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
