# Copyright 2023 Secure Saurce LLC
r"""
==================================================
Deserialization of Untrusted Data in Pandas Module
==================================================

The Python ``pandas`` module is a data analysis and manipulation tool. It
contains a fucntion to read serialized data using the pickle format. Pickle
is not secure because it can be used to deserialize malicious code. For
example, an attacker could create a pickle file that contains malicious
code and then trick a user into opening the file. When the user opens the
file, the malicious code would be executed.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 12

    import pickle
    import pandas as pd


    df = pd.DataFrame(
        {
            "col_A": [1, 2]
        }
    )
    pick = pickle.dumps(df)

    pd.read_pickle(pick)

-----------
Remediation
-----------

Consider signing data with hmac if you need to ensure that pickle data has
not been tampered with.

Alternatively if you need to serialize sensitive data, you could use a secure
serialization format, such as JSON or XML. These formats are designed to be
secure and cannot be used to execute malicious code.

.. seealso::

 - `Deserialization of Untrusted Data in Pandas Module <https://docs.securesauce.dev/rules/PY511>`_
 - `Input_output — pandas <https://pandas.pydata.org/docs/reference/io.html#pickling>`_
 - `CWE-502: Deserialization of Untrusted Data <https://cwe.mitre.org/data/definitions/502.html>`_
 - `pickle — Python object serialization <https://docs.python.org/3/library/pickle.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class PandasReadPickle(Rule):
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
                "pandas.*": [
                    "read_pickle",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["pandas.read_pickle"]:
            return Result(
                rule_id=self.id,
                location=Location(
                    file_name=context["file_name"],
                    node=call.function_node,
                ),
                message=self.message.format(call.name_qualified),
            )
