# Copyright 2024 Secure Saurce LLC
r"""
=======================================================
Use of HTTP Request Method With Sensitive Query Strings
=======================================================

The inclusion of sensitive information, such as a username, password, or API
key, directly within a URL is considered a security risk because URLs can be
logged in various places, such as web server logs, browser history, and network
monitoring tools, making the sensitive information vulnerable to unauthorized
access.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 6

    import http.client


    host = "example.com"
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", "/path?apiKey=value&otherParam=123", headers={})
    response = conn.getresponse()

-----------
Remediation
-----------

To avoid this vulnerability, put sensitive information in the request as
headers, rather than a parameter of the URL.

.. code-block:: python
   :linenos:
   :emphasize-lines: 5-7, 9

    import http.client


    host = "example.com"
    headers = {
        "X-FullContact-APIKey": "value"
    }
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", "/path?otherParam=123", headers=headers)
    response = conn.getresponse()

.. seealso::

 - `http.client — HTTP protocol client <https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection.request>`_
 - `CWE-598: Use of GET Request Method With Sensitive Query Strings <https://cwe.mitre.org/data/definitions/598.html>`_
 - `Never Put Secrets in URLs and Query Parameters <https://www.fullcontact.com/blog/2016/04/29/never-put-secrets-urls-query-parameters/>`_

.. versionadded:: 0.3.4

"""  # noqa: E501
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


SENSITIVE_PARAMS = ("apiKey", "pass", "password", "user", "username")


class HttpUrlSecret(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="sensitive_query_strings",
            full_descr=__doc__,
            cwe_id=598,
            message="Secrets in URLs are vulnerable to unauthorized access.",
            targets=("call"),
            wildcards={
                "http.client": [
                    "HTTPConnection",
                    "HTTPSConnection",
                ]
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "http.client.HTTPConnection.request",
            "http.client.HTTPSConnection.request",
        ]:
            argument = call.get_argument(position=1, name="url")
            url = argument.value
            split_url = urlsplit(url)
            query = split_url.query
            params = parse_qs(query)

            if split_url.username or any(
                key in params for key in SENSITIVE_PARAMS
            ):
                return Result(
                    rule_id=self.id,
                    location=Location(node=argument.node),
                    level=Level.ERROR,
                )
