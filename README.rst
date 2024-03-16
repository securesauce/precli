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

To install precli:

.. code-block:: console

    pip install precli

Run precli on a single test example:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py

Run precli on a single test example, showing results in SARIF format:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py --json

Run precli on a single test example, showing results in plain format:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py --plain

Run precli on a single test example, showing results in markdown format:

.. code-block:: console

    precli tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py --markdown

Run precli against all the python test examples:

.. code-block:: console

    precli -r tests/unit/rules/python/stdlib/examples/

Run precli against an entire GitHub repository:

.. code-block:: console

    precli -r https://github.com/securesauce/precli

Run precli against an entire GitHub repository and output the results in markdown format to Gist.
Note: this requires a GITHUB_TOKEN environment variable set to a valid GitHub token value:

.. code-block:: console

    precli -r https://github.com/securesauce/precli --markdown --gist
