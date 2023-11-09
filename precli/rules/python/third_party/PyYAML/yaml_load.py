# Copyright 2023 Secure Saurce LLC
r"""
======================================================
Deserialization of Untrusted Data in the PyYAML Module
======================================================

The Python ``PyYAML`` module provides a way to parse and generate YAML data.
However, it is important to be aware that malicious YAML strings can be used
to attack applications that use the json module. For example, a malicious YAML
string could be used to cause the decoder to consume considerable CPU and
memory resources, which could lead to a denial-of-service attack.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import yaml


    yaml.load("{}")

-----------
Remediation
-----------

To avoid this vulnerability, it is important to only parse YAML data from
trusted sources. If you are parsing YAML data from an untrusted source, you
should first sanitize the data to remove any potential malicious code. You
can also switch to the ``safe_load`` function or use the ``SafeLoader`` value
to the ``Loader`` argument.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import yaml


    yaml.safe_load("{}")

.. seealso::

 - `Deserialization of Untrusted Data in the PyYAML Module <https://docs.securesauce.dev/rules/PRE0513>`_
 - `PyYAML Documentation <https://pyyaml.org/wiki/PyYAMLDocumentation>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class YamlLoad(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe_id=502,
            message="Usage of '{}' can allow instantiation of arbitrary "
            "objects.",
            targets=("call"),
            wildcards={
                "yaml.*": [
                    "load",
                    "SafeLoader",
                    "CSafeLoader",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["yaml.load"]:
            argument = call.get_argument(position=1, name="Loader")
            loader = argument.value

            if loader is not None:
                if isinstance(loader, str) and loader not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(
                            node=argument.identifier_node
                        ),
                        description="Use 'SafeLoader' as the 'Loader' argument"
                        " to safely load YAML files.",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(
                            file_name=context["file_name"],
                            node=argument.identifier_node,
                        ),
                        message=self.message.format(call.name_qualified),
                        fixes=fixes,
                    )
            else:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=call.identifier_node),
                    description="Use 'yaml.safe_load' to safely load YAML "
                    "files.",
                    inserted_content="safe_load",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.identifier_node,
                    ),
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
