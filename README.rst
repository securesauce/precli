.. image:: https://raw.githubusercontent.com/securesauce/precli/main/images/logo.png
    :alt: Precaution CLI

.. image:: https://github.com/securesauce/precli/actions/workflows/unit-test.yml/badge.svg?branch=main
    :target: https://github.com/securesauce/precli/actions/workflows/unit-test.yml
    :alt: Build and Test

.. image:: https://img.shields.io/pypi/v/precli.svg
    :target: https://pypi.org/project/precli/
    :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/precli.svg
    :target: https://pypi.org/project/precli/
    :alt: Python Versions

.. image:: https://img.shields.io/pypi/dm/precli
    :target: https://pypistats.org/packages/precli
    :alt: PyPI - Downloads

======

Precli is the core of the `Precaution App <https://github.com/marketplace/precaution>`_ and `Precaution Action <https://github.com/marketplace/actions/precaution-action>`_. It also serves as a command line interface to demonstate its functionality. It is designed to do static code analysis of source code with a number of rules covering the standard library for the corresponding programming language.

If your needs go beyond the analysis of just the standard library, consider upgrading to Precaution Professional to get access to finding and fixing security vulnerabilities in third-party libraries. See https://www.securesauce.dev/ for more details.

Quick Start
-----------

To install precli (requires Python 3.12):

.. code-block:: console

    pip install precli

Run precli on a single test example:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py

Example code:

.. code-block:: python

    # level: ERROR
    # start_line: 18
    # end_line: 18
    # start_column: 13
    # end_column: 15
    import hmac


    received_digest = (
        b"\xe2\x93\x08\x19T8\xdc\x80\xef\x87\x90m\x1f\x9d\xf7\xf2"
        b"\xf5\x10>\xdbf\xa2\xaf\xf7x\xcdX\xdf"
    )

    key = b"my-super-duper-secret-key-string"
    password = b"pass"
    digest = hmac.digest(key, password, digest="sha224")

    print(digest == received_digest)

Example result:

.. image:: https://raw.githubusercontent.com/securesauce/precli/main/images/example.gif
    :alt: Example output
