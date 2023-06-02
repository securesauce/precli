Standard Library
================

.. list-table:: Active Rules
   :widths: auto
   :header-rows: 1

   * - ID
     - Module
     - Name
     - Level
   * - :doc:`assert/assert`
     - `assert <https://docs.python.org/3/reference/simple_stmts.html#assert>`_
     - assert
     - Warning
   * - :doc:`crypt/crypt_weak_hash`
     - `crypt <https://docs.python.org/3/library/crypt.html>`_
     - reversible_one_way_hash
     - Warning
   * - :doc:`ftplib/ftp_cleartext`
     - `ftplib <https://docs.python.org/3/library/ftplib.html>`_
     - cleartext_transmission
     - Warning or Error
   * - :doc:`hashlib/hashlib_weak_hash`
     - `hashlib <https://docs.python.org/3/library/hashlib.html>`_
     - reversible_one_way_hash
     - Error
   * - :doc:`hmac/hmac_weak_hash`
     - `hmac <https://docs.python.org/3/library/hmac.html>`_
     - reversible_one_way_hash
     - Error
   * - :doc:`json/json_load`
     - `json <https://docs.python.org/3/library/json.html>`_
     - deserialization_of_untrusted_data
     - Warning
   * - :doc:`logging/insecure_listen_config`
     - `logging <https://docs.python.org/3/library/logging.html>`_
     - code_injection
     - Warning
   * - :doc:`marshal/marshal_load`
     - `marshal <https://docs.python.org/3/library/marshal.html>`_
     - deserialization_of_untrusted_data
     - Warning
   * - :doc:`pickle/pickle_load`
     - `pickle <https://docs.python.org/3/library/pickle.html>`_
     - deserialization_of_untrusted_data
     - Warning
   * - :doc:`shelve/shelve_open`
     - `shelve <https://docs.python.org/3/library/shelve.html>`_
     - deserialization_of_untrusted_data
     - Warning
   * - :doc:`ssl/create_unverified_context`
     - `ssl <https://docs.python.org/3/library/ssl.html>`_
     - improper_certificate_validation
     - Warning
   * - :doc:`ssl/insecure_tls_version`
     - `ssl <https://docs.python.org/3/library/ssl.html>`_
     - inadequate_encryption_strength
     - Error
   * - :doc:`telnetlib/telnetlib_cleartext`
     - `telnetlib <https://docs.python.org/3/library/telnetlib.html>`_
     - cleartext_transmission
     - Error

.. toctree::
   :hidden:
   :maxdepth: 1

   assert/index
   crypt/index
   ftplib/index
   hashlib/index
   hmac/index
   json/index
   logging/index
   marshal/index
   pickle/index
   shelve/index
   ssl/index
   telnetlib/index
