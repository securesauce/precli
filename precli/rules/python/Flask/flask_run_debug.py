# Copyright 2024 Secure Saurce LLC
r"""
==================================
Code Injection in Flask App Config
==================================

Using the ``Flask`` app with debug mode set to True in a production
environment is considered bad for several reasons:

 1.  Security Risk: Debug mode provides detailed error pages with stack traces
     and environment variable information when exceptions occur. This
     information can reveal sensitive data and application internals to
     potential attackers.
 2.  Performance Issues: Debug mode may affect the performance of your Flask
     app. It’s designed for development, not optimized for production traffic.
 3.  Automatic Reloading: Flask’s debug mode includes a feature that
     automatically reloads the application when it detects a code change. This
     is helpful during development but can be disruptive and unpredictable in
     a production environment.
 4.  Exposes Development Tools: Debug mode can enable interactive debugging
     tools (like the Werkzeug debugger), which can be a major security
     vulnerability if exposed publicly.
 5.  Lack of Logging: Relying on debug mode means you might not have proper
     logging set up, which is essential for monitoring and troubleshooting
     production applications.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    from flask import Flask


    app = Flask(__name__)
    app.run(debug=True)

-----------
Remediation
-----------

To avoid this vulnerability, either set the keyword argument of ``debug`` to
False or avoid passing a ``debug`` keyword whenever the intended code is for
production use.

.. code-block:: python
   :linenos:
   :emphasize-lines: 5

    from flask import Flask


    app = Flask(__name__)
    app.run(debug=False)

.. seealso::

 - `Code Injection in Flask App Config <https://docs.securesauce.dev/rules/PY507>`_
 - `Quickstart — Flask Documentation (2.3.x) <https://flask.palletsprojects.com/en/2.3.x/quickstart/#debug-mode>`_
 - `Debugging Applications — Werkzeug Documentation (3.0.x) <https://werkzeug.palletsprojects.com/en/3.0.x/debug/#enabling-the-debugger>`_
 - `How Patreon Got Hacked Publicly Exposed Werkzeug Debugger <https://labs.detectify.com/2015/10/02/how-patreon-got-hacked-publicly-exposed-werkzeug-debugger/>`_
 - `CWE-94: Improper Control of Generation of Code ('Code Injection') <https://cwe.mitre.org/data/definitions/94.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class FlaskRunDebug(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="code_injection",
            full_descr=__doc__,
            cwe_id=94,
            message="Flask debug mode is unsafe as it exposes the Werkzeug "
            "debugger which can allow remote code injection.",
            targets=("call"),
            wildcards={
                "flask.*": [
                    "Flask",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["flask.Flask.run"]:
            argument = call.get_argument(name="debug")
            debug = argument.value

            if debug is True:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.node),
                    description="Turn the debug mode off for code intended "
                    "for production environments.",
                    inserted_content="False",
                )

                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.node,
                    ),
                    level=Level.ERROR,
                    fixes=fixes,
                )
