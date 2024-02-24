Getting Started
===============

Install
-------

To install precli:

.. code-block:: console

    pip install precli


Usage
-----

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

For more usage information:

.. code-block:: console

    precli -h

Version control integration
---------------------------

Use `pre-commit`_. Once you `have it installed`_, add this to the
``.pre-commit-config.yaml`` in your repository
(be sure to update `rev` to point to a `real git tag/revision`_!):

.. code-block:: yaml

    repos:
    - repo: https://github.com/securesauce/precli
      rev: '' # Update me!
      hooks:
      - id: precli

Then run ``pre-commit install`` and you're ready to go.

.. _pre-commit: https://pre-commit.com/
.. _have it installed: https://pre-commit.com/#install
.. _`real git tag/revision`: https://github.com/securesauce/precli/releases
