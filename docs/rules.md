# Rules

## Go Standard Library

| ID | Name | Description |
|----|------|-------------|
| GO001 | [crypto — weak cipher](rules/go/stdlib/crypto-weak-cipher.md) | Use of a Broken or Risky Cryptographic Algorithm in `crypto` Package |
| GO002 | [crypto — weak hash](rules/go/stdlib/crypto-weak-hash.md) | Reversible One Way Hash in `crypto` Package |
| GO003 | [crypto — weak key](rules/go/stdlib/crypto-weak-key.md) | Inadequate Encryption Strength Using Weak Keys in `crypto` Package |

## Java Standard Library

| ID | Name | Description |
|----|------|-------------|
| JAV001 | [javax.crypto — weak cipher](rules/java/stdlib/javax-crypto-weak-cipher.md) | Use of a Broken or Risky Cryptographic Algorithm in `javax.crypto` Package |
| JAV002 | [java.security — weak hash](rules/java/stdlib/java-security-weak-hash.md) | Reversible One Way Hash in `java.security` Package |
| JAV003 | [java.security — weak key](rules/java/stdlib/java-security-weak-key.md) | Inadequate Encryption Strength Using Weak Keys in `java.security` Package |
| JAV004 | [java.security — weak random](rules/java/stdlib/java-security-weak-random.md) | Use of Cryptographically Weak Pseudo-Random Number Generator `SHA1PRNG` |
| JAV005 | [javax.servlet.http — insecure cookie](rules/java/stdlib/javax-servlet-http-insecure-cookie.md) | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |
| JAV006 | [java.net — insecure cookie](rules/java/stdlib/java-net-insecure-cookie.md) | Sensitive Cookie in HTTPS Session Without 'Secure' Attribute |

## Python Standard Library

| ID | Name | Description |
|----|------|-------------|
| PY001 | [assert](rules/python/stdlib/assert.md) | Improper Check Using `assert` Function |
| PY002 | [crypt — weak hash](rules/python/stdlib/crypt-weak-hash.md) | Reversible One Way Hash in `crypt` Module |
| PY003 | [ftplib — cleartext](rules/python/stdlib/ftplib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `ftplib` Module |
| PY004 | [hashlib — weak hash](rules/python/stdlib/hashlib-weak-hash.md) | Reversible One Way Hash in `hashlib` Module |
| PY005 | [hmac — timing attack](rules/python/stdlib/hmac-timing-attack.md) | Observable Timing Discrepancy in `hmac` Module |
| PY006 | [hmac — weak hash](rules/python/stdlib/hmac-weak-hash.md) | Reversible One Way Hash in `hmac` Module |
| PY007 | [http — secret in url](rules/python/stdlib/http-url-secret.md) | Use of HTTP Request Method With Sensitive Query Strings |
| PY008 | [imaplib — cleartext](rules/python/stdlib/imaplib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `imaplib` Module |
| PY009 | [json — load](rules/python/stdlib/json-load.md) | Deserialization of Untrusted Data in the `json` Module |
| PY010 | [logging — insecure listen config](rules/python/stdlib/logging-insecure-listen-config.md) | Code Injection in Logging Config |
| PY011 | [marshal — load](rules/python/stdlib/marshal-load.md) | Deserialization of Untrusted Data in the `marshal` Module |
| PY012 | [nntplib — cleartext](rules/python/stdlib/nntplib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `nntplib` Module |
| PY013 | [pickle — load](rules/python/stdlib/pickle-load.md) | Deserialization of Untrusted Data in `pickle` Module |
| PY014 | [poplib — cleartext](rules/python/stdlib/poplib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `poplib` Module |
| PY015 | [shelve — open](rules/python/stdlib/shelve-open.md) | Deserialization of Untrusted Data in the `shelve` Module |
| PY016 | [smtplib — cleartext](rules/python/stdlib/smtplib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `smtplib` Module |
| PY017 | [ssl — unverified context](rules/python/stdlib/ssl-create-unverified-context.md) | Inadequate Encryption Strength Using Weak Keys in `SSLContext` |
| PY018 | [ssl — insecure tls version](rules/python/stdlib/ssl-insecure-tls-version.md) | Improper Certificate Validation Using `ssl._create_unverified_context` |
| PY019 | [ssl — weak key](rules/python/stdlib/ssl-context-weak-key.md) | Inadequate Encryption Strength Using Weak SSL Protocols |
| PY020 | [telnetlib — cleartext](rules/python/stdlib/telnetlib-cleartext.md) | Cleartext Transmission of Sensitive Information in the `telnetlib` Module |
| PY021 | [tempfile — mktemp race condition](rules/python/stdlib/tempfile-mktemp-race-condition.md) | Insecure Temporary File in the ``tempfile`` Module |
| PY022 | [ftplib — unverified context](rules/python/stdlib/ftplib-unverified-context.md) | Improper Certificate Validation Using `ftplib` |
| PY023 | [imaplib — unverified context](rules/python/stdlib/imaplib-unverified-context.md) | Improper Certificate Validation Using `imaplib` |
| PY024 | [nntplib — unverified context](rules/python/stdlib/nntplib-unverified-context.md) | Improper Certificate Validation Using `nntplib` |
| PY025 | [poplib — unverified context](rules/python/stdlib/poplib-unverified-context.md) | Improper Certificate Validation Using `poplib` |
| PY026 | [smtplib — unverified context](rules/python/stdlib/smtplib-unverified-context.md) | Improper Certificate Validation Using `smtplib` |
| PY027 | [argparse — sensitive info](rules/python/stdlib/argparse-sensitive-info.md) | Invocation of Process Using Visible Sensitive Information in `argparse` |
| PY028 | [secrets — weak token](rules/python/stdlib/secrets-weak-token.md) | Insufficient Token Length |
| PY029 | [socket — unrestricted bind](rules/python/stdlib/socket-unrestricted-bind.md) | Binding to an Unrestricted IP Address in `socket` Module |
| PY030 | [socketserver — unrestricted bind](rules/python/stdlib/socketserver-unrestricted-bind.md) | Binding to an Unrestricted IP Address in `socketserver` Module |
| PY031 | [http — unrestricted bind](rules/python/stdlib/http-server-unrestricted-bind.md) | Binding to an Unrestricted IP Address in `http.server` Module |
| PY032 | [xmlrpc — unrestricted bind](rules/python/stdlib/xmlrpc-server-unrestricted-bind.md) | Binding to an Unrestricted IP Address in `xmlrpc.server` Module |
| PY033 | [re — denial of service](rules/python/stdlib/re-denial-of-service.md) | Inefficient Regular Expression Complexity in `re` Module |
| PY034 | [hmac — weak key](rules/python/stdlib/hmac-weak-key.md) | Insufficient `hmac` Key Size |
| PY035 | [hashlib — improper prng](rules/python/stdlib/hashlib-improper-prng.md) | Improper Randomness for Cryptographic `hashlib` Functions |
