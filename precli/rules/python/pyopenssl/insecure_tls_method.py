# Copyright 2023 Secure Saurce LLC
r"""
=======================================================
Inadequate Encryption Strength Using Weak SSL Protocols
=======================================================

The Python ``pyopenssl`` modules provide a number of different methods that
can be used to encrypt data. However, some of these methods are no longer
considered secure and should not be used.

The following protocols are considered weak and should not be used:

- SSLv2_METHOD
- SSLv3_METHOD
- TLSv1_METHOD
- TLSv1_1_METHOD

These protocols have a number of known security vulnerabilities that can be
exploited by attackers. For example, the BEAST attack can be used to steal
sensitive data, such as passwords and credit card numbers, from applications
that use SSL version 2.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import OpenSSL


    OpenSSL.SSL.Context(method=OpenSSL.SSL.SSLv2_METHOD)

-----------
Remediation
-----------

If you need to connect to a server over HTTPS, you should use the
``TLS_METHOD``, ``TLS_SERVER_METHOD``, or ``TLS_CLIENT_METHOD`` methods
instead. The ``SSLv23_METHOD`` and ``TLSv1_2_METHOD`` methods are also
considered secure, but the aforementioned methods are more future proof as
they negotiate a secure version of the method for you.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import OpenSSL


    OpenSSL.SSL.Context(method=OpenSSL.SSL.TLS_METHOD)

.. seealso::

 - `Inadequate Encryption Strength Using Weak SSL Protocols <https://docs.securesauce.dev/rules/PY519>`_
 - `pyOpenSSL’s documentation <https://www.pyopenssl.org/en/latest/>`_
 - `CWE-326: Inadequate Encryption Strength <https://cwe.mitre.org/data/definitions/326.html>`_

.. versionadded:: 1.0.0

"""  # noqa: E501
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


INSECURE_METHODS = (
    "OpenSSL.SSL.SSLv2_METHOD",
    "OpenSSL.SSL.SSLv3_METHOD",
    "OpenSSL.SSL.TLSv1_METHOD",
    "OpenSSL.SSL.TLSv1_1_METHOD",
)


class InsecureTlsMethod(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="inadequate_encryption_strength",
            full_descr=__doc__,
            cwe_id=326,
            message="The '{}' method has insufficient encryption strength.",
            targets=("call"),
            wildcards={
                "OpenSSL.SSL.*": [
                    "Context",
                    "SSLv2_METHOD",
                    "SSLv3_METHOD",
                    "TLSv1_METHOD",
                    "TLSv1_1_METHOD",
                ],
                "OpenSSL.*": [
                    "SSL.Context",
                    "SSL.SSLv2_METHOD",
                    "SSL.SSLv3_METHOD",
                    "SSL.TLSv1_METHOD",
                    "SSL.TLSv1_1_METHOD",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["OpenSSL.SSL.Context"]:
            argument = call.get_argument(position=1, name="method")
            method = argument.value

            if isinstance(method, str) and method in INSECURE_METHODS:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=argument.identifier_node),
                    description="Use 'TLS_METHOD' to auto-negotiate the "
                    "highest protocol version that both the client and "
                    "server support.",
                    inserted_content="TLS_METHOD",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format(method),
                    fixes=fixes,
                )
