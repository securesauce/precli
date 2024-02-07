# Copyright 2024 Secure Saurce LLC
r"""
==================================================
Deserialization of Untrusted Data in Pickle Module
==================================================

The Python ``pickle`` module is a serialization module that can be used to
serialize and deserialize Python objects. However, pickle is not a secure
serialization format and should not be used to serialize sensitive data.

Pickle is not secure because it can be used to deserialize malicious code. For
example, an attacker could create a pickle file that contains malicious code
and then trick a user into opening the file. When the user opens the file,
the malicious code would be executed.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 9

    import pickle


    def load_pickle_file(file_path):
        with open(file_path, 'rb') as file:
            data = file.read()

        # WARNING: Unpickle data without proper validation
        obj = pickle.loads(data)
        return obj

    # Example usage (assuming 'malicious.pickle' contains malicious code)
    pickle_file = 'malicious.pickle'
    loaded_object = load_pickle_file(pickle_file)

-----------
Remediation
-----------

Consider signing data with hmac if you need to ensure that pickle data has
not been tampered with.

Alternatively if you need to serialize sensitive data, you could use a
secure serialization format, such as JSON or XML. These formats are designed
to be secure and cannot be used to execute malicious code.

.. seealso::

 - `pickle — Python object serialization <https://docs.python.org/3/library/pickle.html>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_
 - `json — JSON encoder and decoder <https://docs.python.org/3/library/json.html>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PickleLoad(Rule):
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
                "pickle.*": [
                    "load",
                    "loads",
                    "Unpickler",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "pickle.load",
            "pickle.loads",
            "pickle.Unpickler",
        ]:
            return Result(
                rule_id=self.id,
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
            )
