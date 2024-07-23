# Copyright 2024 Secure Sauce LLC
r"""
# Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

This rule identifies and flags any instance where cookies in Java web
applications are created or set without the Secure flag. The absence of this
flag allows the cookie to be transmitted over non-HTTPS connections, which
poses a risk of interception by an attacker, especially through
man-in-the-middle (MITM) attacks.

Cookies are often used to store sensitive information such as session
identifiers and personal data. When a cookie is set without the Secure flag,
it can be sent over both secure (HTTPS) and insecure (HTTP) connections.
This vulnerability exposes the cookie to potential interception when
transmitted over an insecure connection. To mitigate this risk, the Secure
flag should be set on all cookies that are intended for HTTPS sites, ensuring
they are only sent via secure connections.

# Example

```java linenums="1" hl_lines="8" title="HttpCookieSecureFalse.java"
import java.net.*;


public class HttpCookieSecureFalse {
    public static void main(String[] args) {
        HttpCookie cookie = new HttpCookie("cookieName", "cookieValue");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
    }
}
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/java/stdlib/java_net/examples/HttpCookieSecureFalse.java
    ⚠️  Warning on line 8 in tests/unit/rules/java/stdlib/java_net/examples/HttpCookieSecureFalse.java
    JAV006: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
    The cookie 'cookie' was found without the 'Secure' flag set.
    ```

# Remediation

All cookies containing sensitive data or used in a secure context must have
the Secure flag enabled. This practice ensures that the cookies are
transmitted only over HTTPS, providing protection against eavesdropping and
MITM attacks on the communication channel.

```java linenums="1" hl_lines="8" title="HttpCookieSecureFalse.java"
import java.net.*;


public class HttpCookieSecureFalse {
    public static void main(String[] args) {
        HttpCookie cookie = new HttpCookie("cookieName", "cookieValue");
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
    }
}
```

# See also

!!! info
    - [HttpCookie (Java SE & JDK))](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/net/HttpCookie.html)
    - [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (PRNG)](https://cwe.mitre.org/data/definitions/614.html)

_New in version 0.5.1_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class InsecureCookie(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="insecure_cookie",
            description=__doc__,
            cwe_id=614,
            message="The cookie '{0}' was found without the 'Secure' flag "
            "set.",
            wildcards={
                "java.net.*": [
                    "HttpCookie",
                ],
            },
        )

    def analyze_method_invocation(
        self, context: dict, call: Call
    ) -> Result | None:
        if call.name_qualified not in [
            "java.net.HttpCookie.setSecure",
        ]:
            return

        argument = call.get_argument(position=0)
        secure = argument.value

        if secure is True:
            return

        fixes = Rule.get_fixes(
            context=context,
            deleted_location=Location(node=argument.node),
            description="Set the 'Secure' flag to True on all cookies.",
            inserted_content="true",
        )
        return Result(
            rule_id=self.id,
            location=Location(node=argument.node),
            message=self.message.format(call.var_node.text.decode()),
            fixes=fixes,
        )
