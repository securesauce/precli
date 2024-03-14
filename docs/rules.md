# Rules

## Go Standard Library

| ID | Name | Description |
|----|------|-------------|
| GO001 | [crypto — weak cipher](rules/go/stdlib/crypto_weak_cipher.md) | Use of a Broken or Risky Cryptographic Algorithm in `crypto` Package |
| GO002 | [crypto — weak hash](rules/go/stdlib/crypto_weak_hash.md) | Reversible One Way Hash in `crypto` Package |
| GO003 | [crypto — weak key](rules/go/stdlib/crypto_weak_key.md) | Inadequate Encryption Strength Using Weak Keys in `crypto` Package |

## Python Standard Library

| ID | Name | Description |
|----|------|-------------|
| PY001 | [assert](rules/python/stdlib/assert.md) | Improper Check Using `assert` Function |
| PY002 | [crypt — weak hash](rules/python/stdlib/crypt_weak_hash.md) | Reversible One Way Hash in `crypt` Module |
| PY003 | [ftplib — cleartext](rules/python/stdlib/ftplib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `ftplib` Module |
| PY004 | [hashlib — weak hash](rules/python/stdlib/hashlib_weak_hash.md) | Reversible One Way Hash in `hashlib` Module |
| PY005 | [hmac — timing attack](rules/python/stdlib/hmac_timing_attack.md) | Observable Timing Discrepancy in `hmac` Module |
| PY006 | [hmac — weak hash](rules/python/stdlib/hmac_weak_hash.md) | Reversible One Way Hash in `hmac` Module |
| PY007 | [http — secret in url](rules/python/stdlib/http_url_secret.md) | Use of HTTP Request Method With Sensitive Query Strings |
| PY008 | [imaplib — cleartext](rules/python/stdlib/imaplib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `imaplib` Module |
| PY009 | [json — load](rules/python/stdlib/json_load.md) | Deserialization of Untrusted Data in the `json` Module |
| PY010 | [logging — insecure listen config](rules/python/stdlib/logging_insecure_listen_config.md) | Code Injection in Logging Config |
| PY011 | [marshal — load](rules/python/stdlib/marshal_load.md) | Deserialization of Untrusted Data in the `marshal` Module |
| PY012 | [nntplib — cleartext](rules/python/stdlib/nntplib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `nntplib` Module |
| PY013 | [pickle — load](rules/python/stdlib/pickle_load.md) | Deserialization of Untrusted Data in `pickle` Module |
| PY014 | [poplib — cleartext](rules/python/stdlib/poplib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `poplib` Module |
| PY015 | [shelve — open](rules/python/stdlib/shelve_open.md) | Deserialization of Untrusted Data in the `shelve` Module |
| PY016 | [smtplib — cleartext](rules/python/stdlib/smtplib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `smtplib` Module |
| PY017 | [ssl — create unverified context](rules/python/stdlib/ssl_create_unverified_context.md) | Inadequate Encryption Strength Using Weak Keys in `SSLContext` |
| PY018 | [ssl — insecure tls version](rules/python/stdlib/ssl_insecure_tls_version.md) | Improper Certificate Validation Using `ssl._create_unverified_context` |
| PY019 | [ssl — weak key](rules/python/stdlib/ssl_context_weak_key.md) | Inadequate Encryption Strength Using Weak SSL Protocols |
| PY020 | [telnetlib — cleartext](rules/python/stdlib/telnetlib_cleartext.md) | Cleartext Transmission of Sensitive Information in the `telnetlib` Module |
| PY021 | [tempfile — mktemp race condition](rules/python/stdlib/tempfile_mktemp_race_condition.md) | Insecure Temporary File in the ``tempfile`` Module |
| PY022 | [ftplib — unverified context](rules/python/stdlib/ftplib_unverified_context.md) | Improper Certificate Validation Using `ftplib` |
| PY023 | [imaplib — unverified context](rules/python/stdlib/imaplib_unverified_context.md) | Improper Certificate Validation Using `imaplib` |
| PY024 | [nntplib — unverified context](rules/python/stdlib/nntplib_unverified_context.md) | Improper Certificate Validation Using `nntplib` |
| PY025 | [poplib — unverified context](rules/python/stdlib/poplib_unverified_context.md) | Improper Certificate Validation Using `poplib` |
| PY026 | [smtplib — unverified context](rules/python/stdlib/smtplib_unverified_context.md) | Improper Certificate Validation Using `smtplib` |
