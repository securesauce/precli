# Copyright 2024 Secure Saurce LLC
r"""
====================================================================
Improper Certificate Validation Using ssl._create_unverified_context
====================================================================

The Python function ``ssl._create_unverified_context()`` creates a SSL context
that does not verify the server's certificate. This means that an attacker can
easily impersonate a legitimate server and fool your application into
connecting to it.

If you use ``ssl._create_unverified_context``, you are opening your application
up to a number of security risks, including:

- Man-in-the-middle attacks
- Session hijacking
- Data theft

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import ssl


    context = ssl._create_unverified_context()

-----------
Remediation
-----------

If you need to connect to a server over HTTPS, you should use the
``ssl.create_default_context()`` function instead. This function will verify
the server's certificate, which will help to protect your application from
these security risks.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import ssl


    context = ssl.create_default_context()

.. seealso::

 - `ssl — TLS/SSL wrapper for socket objects <https://docs.python.org/3/library/ssl.html>`_
 - `CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>`_

.. versionadded:: 0.1.0

"""  # noqa: E501
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class CreateUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' function does not properly validate "
            "certificates.",
            targets=("call"),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        """
        _create_unverified_context(
            protocol=None,
            *,
            cert_reqs=<VerifyMode.CERT_NONE: 0>,
            check_hostname=False,
            purpose=<Purpose.SERVER_AUTH: _ASN1Object(
                nid=129,
                shortname='serverAuth',
                longname='TLS Web Server Authentication',
                oid='1.3.6.1.5.5.7.3.1'
            )>,
            certfile=None,
            keyfile=None,
            cafile=None,
            capath=None,
            cadata=None
        )
        create_default_context(
            purpose=<Purpose.SERVER_AUTH: _ASN1Object(
                nid=129,
                shortname='serverAuth',
                longname='TLS Web Server Authentication',
                oid='1.3.6.1.5.5.7.3.1'
            )>,
            *,
            cafile=None,
            capath=None,
            cadata=None
        )
        """
        call = kwargs.get("call")

        if call.name_qualified in ["ssl._create_unverified_context"]:
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=call.identifier_node),
                description="Use 'create_default_context' to safely validate "
                "certificates.",
                inserted_content="create_default_context",
            )
            return Result(
                rule_id=self.id,
                artifact=context["artifact"],
                location=Location(node=call.function_node),
                message=self.message.format(call.name_qualified),
                fixes=fixes,
            )
