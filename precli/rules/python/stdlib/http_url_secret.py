# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
r"""
# Use of HTTP Request Method With Sensitive Query Strings

The inclusion of sensitive information, such as a username, password, or API
key, directly within a URL is considered a security risk because URLs can be
logged in various places, such as web server logs, browser history, and network
monitoring tools, making the sensitive information vulnerable to unauthorized
access.

# Example

```python linenums="1" hl_lines="7" title="http_url_secret_apikey.py"
import http.client


host = "example.com"
conn = http.client.HTTPSConnection(host)
conn.request(
    "GET", "/path?apiKey=value&otherParam=123", headers={"Host": host}
)
response = conn.getresponse()
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/http/examples/http_url_secret_apikey.py
    ⛔️ Error on line 7 in tests/unit/rules/python/stdlib/http/examples/http_url_secret_apikey.py
    PY007: Use of GET Request Method With Sensitive Query Strings
    Secrets in URLs are vulnerable to unauthorized access.
    ```

# Remediation

To avoid this vulnerability, put sensitive information in the request as
headers, rather than a parameter of the URL.

```python linenums="1" hl_lines="7 10" title="http_url_secret_apikey.py"
import http.client


host = "example.com"
headers = {
    "Host": host,
    "X-FullContact-APIKey": "value"
}
conn = http.client.HTTPSConnection(host)
conn.request("GET", "/path?otherParam=123", headers=headers)
response = conn.getresponse()
```

# Default Configuration

```toml
enabled = true
level = "error"
sensitive_params = [
  "apiKey",
  "pass",
  "password",
  "user",
  "username",
]
```

# See also

!!! info
    - [http.client — HTTP protocol client](https://docs.python.org/3/library/http.client.html#http.client.HTTPConnection.request)
    - [CWE-598: Use of GET Request Method With Sensitive Query Strings](https://cwe.mitre.org/data/definitions/598.html)
    - [Never Put Secrets in URLs and Query Parameters](https://www.fullcontact.com/blog/2016/04/29/never-put-secrets-urls-query-parameters/)

_New in version 0.3.4_

"""  # noqa: E501
from typing import Optional
from urllib.parse import parse_qs
from urllib.parse import urlsplit

from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.i18n import _
from precli.rules import Rule


class HttpUrlSecret(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="sensitive_query_strings",
            description=__doc__,
            cwe_id=598,
            message=_(
                "Secrets in URLs are vulnerable to unauthorized access."
            ),
        )

    def analyze_call(self, context: dict, call: Call) -> Optional[Result]:
        if call.name_qualified not in [
            "http.client.HTTPConnection.request",
            "http.client.HTTPSConnection.request",
        ]:
            return

        argument = call.get_argument(position=1, name="url")
        if argument.is_str is False:
            return

        url = argument.value_str
        split_url = urlsplit(url)
        query = split_url.query
        params = parse_qs(query)

        if split_url.username or any(
            key in params
            for key in self.config.parameters.get("sensitive_params")
        ):
            return Result(
                rule_id=self.id,
                location=Location(node=argument.node),
            )
