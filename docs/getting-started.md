# Getting Started


## Install

To install precli:

```
pip install precli
```

## Usage

Run precli on a single test example:

```
precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py
```

Run precli on a single test example, showing results in SARIF format:

```
precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py --json
```

Run precli on a single test example, showing results in plain format:

```
precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py --plain
```

Run precli on a single test example, showing results in markdown format:

```
precli tests/unit/rules/python/stdlib/hmac/examples/hmac_timing_attack.py --markdown
```

Run precli against all the python test examples:

```
precli -r tests/unit/rules/python/
```

Run precli against an entire GitHub repository:

```
precli -r https://github.com/securesauce/precli
```

Run precli against an entire GitHub repository and output the results in
markdown format to Gist. Note: this requires a GITHUB_TOKEN environment
variable set to a valid GitHub token value:

```
precli -r https://github.com/securesauce/precli --markdown --gist
```

For more usage information:

```
precli -h
```

## Version control integration

Use [pre-commit](https://pre-commit.com/). Once you have it installed, add
this to the `.pre-commit-config.yaml` in your repository
(be sure to update `rev` to point to a real git tag/revision!):


```
repos:
- repo: https://github.com/securesauce/precli
  rev: '' # Update me!
  hooks:
  - id: precli
```

Then run `pre-commit install` and you're ready to go.
