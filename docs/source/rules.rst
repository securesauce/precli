Rules
=====

.. list-table:: Go Standard Library
   :widths: auto
   :header-rows: 1

   * - ID
     - Name
     - Description
   * - GO001
     - :doc:`rules/go/stdlib/crypto_weak_cipher`
     - Use of a Broken or Risky Cryptographic Algorithm in ``crypto`` Package
   * - GO002
     - :doc:`rules/go/stdlib/crypto_weak_hash`
     - Reversible One Way Hash in ``crypto`` Package
   * - GO003
     - :doc:`rules/go/stdlib/crypto_weak_key`
     - Inadequate Encryption Strength Using Weak Keys in ``crypto`` Package

.. list-table:: Python Standard Library
   :widths: auto
   :header-rows: 1

   * - ID
     - Name
     - Description
   * - PY001
     - :doc:`rules/python/stdlib/assert`
     -
   * - PY002
     - :doc:`rules/python/stdlib/crypt_weak_hash`
     - Reversible One Way Hash in ``crypt`` Module
   * - PY003
     - :doc:`rules/python/stdlib/ftplib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``ftplib`` Module
   * - PY004
     - :doc:`rules/python/stdlib/hashlib_weak_hash`
     - Reversible One Way Hash in ``hashlib`` Module
   * - PY005
     - :doc:`rules/python/stdlib/hmac_timing_attack`
     - Observable Timing Discrepancy in ``hmac`` Module
   * - PY006
     - :doc:`rules/python/stdlib/hmac_weak_hash`
     - Reversible One Way Hash in ``hmac`` Module
   * - PY007
     - :doc:`rules/python/stdlib/http_url_secret`
     - Use of HTTP Request Method With Sensitive Query Strings
   * - PY008
     - :doc:`rules/python/stdlib/imaplib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``imaplib`` Module
   * - PY009
     - :doc:`rules/python/stdlib/json_load`
     - Deserialization of Untrusted Data in the ``json`` Module
   * - PY010
     - :doc:`rules/python/stdlib/logging_insecure_listen_config`
     - Code Injection in Logging Config
   * - PY011
     - :doc:`rules/python/stdlib/marshal_load`
     - Deserialization of Untrusted Data in the ``marshal`` Module
   * - PY012
     - :doc:`rules/python/stdlib/nntplib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``nntplib`` Module
   * - PY013
     - :doc:`rules/python/stdlib/pickle_load`
     - Deserialization of Untrusted Data in ``pickle`` Module
   * - PY014
     - :doc:`rules/python/stdlib/poplib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``poplib`` Module
   * - PY015
     - :doc:`rules/python/stdlib/shelve_open`
     - Deserialization of Untrusted Data in the ``shelve`` Module
   * - PY016
     - :doc:`rules/python/stdlib/smtplib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``smtplib`` Module
   * - PY017
     - :doc:`rules/python/stdlib/ssl_create_unverified_context`
     - Inadequate Encryption Strength Using Weak Keys in ``SSLContext``
   * - PY018
     - :doc:`rules/python/stdlib/ssl_insecure_tls_version`
     - Improper Certificate Validation Using ``ssl._create_unverified_context``
   * - PY019
     - :doc:`rules/python/stdlib/ssl_context_weak_key`
     - Inadequate Encryption Strength Using Weak SSL Protocols
   * - PY020
     - :doc:`rules/python/stdlib/telnetlib_cleartext`
     - Cleartext Transmission of Sensitive Information in the ``telnetlib`` Module
   * - PY021
     - :doc:`rules/python/stdlib/tempfile_mktemp_race_condition`
     - Insecure Temporary File in the ``tempfile`` Module
