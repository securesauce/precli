.. image:: https://raw.githubusercontent.com/securesauce/precli/main/images/logo.png
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

Note: If using arm based macOS, you'll also need to install this package:

.. code-block:: console

    pip install git+https://github.com/tree-sitter/tree-sitter-python@v0.21.0

Run precli on a single test example:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py

Example result:

.. image:: https://raw.githubusercontent.com/securesauce/precli/main/images/example.gif
    :alt: Example output

Repo Activity
-------------

.. image:: https://repobeats.axiom.co/api/embed/e7b91dc06cef0f5076264bc799a37fc4b7eed186.svg
    :alt: Repobeats analytics image
