# Copyright 2023 Secure Saurce LLC
r"""
================================
Code Injection in Logging Config
================================

The ``logging.config.listen()`` function allows you to dynamically change the
logging configuration of your application. However, if you set the verify
argument to False, you are opening yourself up to a security vulnerability.
This is because anyone who can connect to the listening socket can send
arbitrary configuration data to your application, which could potentially
allow them to execute arbitrary code.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import logging.config


    thread = logging.config.listen(port=1111, verify=None)

-----------
Remediation
-----------

The verify argument should be set to a callable function that should verify
whether bytes received on the socket are valid to be processed. One way to
verify the data is to use encryption and/or signing.

.. code-block:: python
   :linenos:
   :emphasize-lines: 8

    import logging.config


    def validate(recv: bytes):
        return recv


    thread = logging.config.listen(verify=validate)


.. seealso::

 - `logging.config — Logging configuration <https://docs.python.org/3/library/logging.config.html#module-logging.config>`_
 - `CWE-94: Improper Control of Generation of Code ('Code Injection') <https://cwe.mitre.org/data/definitions/94.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class InsecureListenConfig(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="code_injection",
            full_descr=__doc__,
            cwe_id=94,
            message="Using '{}' with unset 'verify' vulnerable to code "
            "injection.",
            targets=("call"),
            wildcards={
                "logging.config.*": [
                    "listen",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["logging.config.listen"]):
            call_args = context["func_call_args"]
            call_kwargs = context["func_call_kwargs"]
            verify = (
                call_args[1]
                if len(call_args) > 1
                else call_kwargs.get("verify", None)
            )

            if verify is None:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        context["file_name"], kwargs.get("func_node")
                    ),
                    message=self.message.format(kwargs.get("func_call_qual")),
                )
