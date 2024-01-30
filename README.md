# Precli - precaution command line interface

[![Build and Test](https://github.com/securesauce/precli/actions/workflows/unit-test.yml/badge.svg?branch=main)](https://github.com/securesauce/precli/actions/workflows/unit-test.yml)

Precli is the core of the GitHub App [Precaution](https://github.com/marketplace/precaution) and also a command line interface to demonstate its functionality.

**Quick Start**
```bash
pip install precli
```

**Example**

```
$ precli tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py
⛔️ Error on line 18 in tests/unit/rules/python/stdlib/examples/hmac_timing_attack.py
PY005: Observable Timing Discrepancy
Comparing digests with the '==' operator is vulnerable to timing attacks.
  17
❱ 18 return digest == received_digest
  19
Suggested fix: Use the 'hmac.compare_digest' function instead of the '=='' operator to reduce the
vulnerability to timing attacks.
  17
❱ 18 return hmac.compare_digest(digest, received_digest)
  19

┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━┓
┃ Files analyzed        ┃   1 ┃ Lines analyzed       ┃  18 ┃
┃ Files skipped         ┃   0 ┃                      ┃     ┃
┣━━━━━━━━━━━━━━━━━━━━━━━╋━━━━━╋━━━━━━━━━━━━━━━━━━━━━━╋━━━━━┫
┃ Errors                ┃   1 ┃                      ┃     ┃
┃ Warnings              ┃   0 ┃                      ┃     ┃
┃ Notes                 ┃   0 ┃                      ┃     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━┻━━━━━┻━━━━━━━━━━━━━━━━━━━━━━┻━━━━━┛
```
