# Copyright 2024 Secure Sauce LLC
r"""
# Invocation of Process Using Visible Sensitive Information in `argparse`

Do not read secrets directly from command line arguments. When a command
accepts a secret like via a `--password` argument or `--api-key`, the argument
value will leak the secret into ps output and shell history. This also
encourages the use of insecure environment variables for secrets.

## Example

```python
import argparse


parser = argparse.ArgumentParser(
    prog='ProgramName',
    description='What the program does',
)
parser.add_argument(
    "-p",
    "--password",
    dest="password",
    action="store",
    help="password for the database",
)
```

## Remediation

Consider accepting sensitive data only from an interactive hidden prompt or
via files. A --password-file argument allows a secret to be passed in
discreetly, in a wide variety of contexts.

```python
import argparse


parser = argparse.ArgumentParser(
    prog='ProgramName',
    description='What the program does',
)
parser.add_argument(
    "-p",
    "--password",
    dest="password",
    action="store_true",
    help="password for the database",
)
```

## See also

- [argparse — Parser for command-line options, arguments and sub-commands](https://docs.python.org/3/library/argparse.html)
- [CWE-214: Invocation of Process Using Visible Sensitive Information](https://cwe.mitre.org/data/definitions/214.html)

_New in version 0.3.14_

_Changed in version 0.4.1: --api-key also checked_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class ArgparseSensitiveInfo(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="visible_sensitive_information",
            description=__doc__,
            cwe_id=214,
            message="{0} in CLI arguments are leaked to command history, "
            "logs, ps output, etc.",
            wildcards={
                "argparse.*": [
                    "ArgumentParser",
                ]
            },
            config=Config(level=Level.ERROR),
        )

    def analyze_call(self, context: dict, call: Call) -> Result:
        if call.name_qualified not in [
            "argparse.ArgumentParser.add_argument",
        ]:
            return

        # add_argument(*args, **kwargs)
        # add_argument(dest, ..., name=value, ...)
        # add_argument(option_string, option_string, ..., name=value, ...)
        arg0 = call.get_argument(position=0)
        arg1 = call.get_argument(position=1)
        action = call.get_argument(name="action")

        if (
            "--password" in [arg0.value_str, arg1.value_str]
            or "--api-key" in [arg0.value_str, arg1.value_str]
            or "--token" in [arg0.value_str, arg1.value_str]
        ) and (action.value is None or action.value_str == "store"):
            return Result(
                rule_id=self.id,
                location=Location(node=call.node),
                message=self.message.format("Secrets"),
            )
