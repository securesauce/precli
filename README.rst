.. image:: https://raw.githubusercontent.com/securesauce/precli/main/logo/logo.png
    :alt: Precaution CLI

======

.. image:: https://github.com/securesauce/precli/actions/workflows/unit-test.yml/badge.svg?branch=main
    :target: https://github.com/securesauce/precli/actions/workflows/unit-test.yml
    :alt: Build and Test

Precli is the core of the Precaution GitHub App and Action. It also serves as a command line interface to demonstate its functionality. It is designed to do static code analysis of source code with a number of rules covering the standard library for the corresponding programming language.

If your needs go beyond the analysis of just the standard library, consider upgrading to Precaution Professional to get access to finding and fixing security vulnerabilities in third-party libraries. See https://www.securesauce.dev/ for more details.

Quick Start
-----------

To install precli (requires Python 3.12):

.. code-block:: console

    pip install precli

Run precli on a single test example:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py

Example result:

.. code-block:: console

    ⛔️ Error on line 18 in tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py
    PY005: Observable Timing Discrepancy
    Comparing digests with the '==' operator is vulnerable to timing attacks.
      17
    ❱ 18 print(digest == received_digest)
      19
    Suggested fix: Use the 'hmac.compare_digest' function instead of the '==' operator to reduce the
    vulnerability to timing attacks.
      17
    ❱ 18 print(hmac.compare_digest(digest, received_digest))
      19
