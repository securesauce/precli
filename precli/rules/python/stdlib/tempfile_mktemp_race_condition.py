# Copyright 2024 Secure Sauce LLC
r"""
# Insecure Temporary File in the `tempfile` Module

The `tempfile.mktemp` function in Python is a legacy method for creating
temporary files with a unique name. It is important to note that this function
is susceptible to race conditions, which can occur when multiple processes or
threads attempt to create temporary files concurrently. These race conditions
may lead to unintended behavior, data corruption, or security vulnerabilities
in your code.

# Example

```python linenums="1" hl_lines="4" title="tempfile_mktemp_args_with_open_args.py"
import tempfile


filename = tempfile.mktemp("", "tmp", dir=None)
with open(
    filename, "w+", buffering=-1, encoding=None, errors=None, newline=None
) as f:
    f.write(b"Hello World!\n")
```

??? example "Example Output"
    ```
    > precli tests/unit/rules/python/stdlib/tempfile/examples/tempfile_mktemp_args_with_open_args.py
    ⚠️  Warning on line 4 in tests/unit/rules/python/stdlib/tempfile/examples/tempfile_mktemp_args_with_open_args.py
    PY021: Insecure Temporary File
    The function 'tempfile.mktemp' can allow insecure ways of creating temporary files and directories that can lead to race conditions.
    ```

# Remediation

To ensure the reliability and security of your temporary file management,
consider using NamedTemporaryFile. The tempfile.NamedTemporaryFile class
automatically handles the generation of unique filenames, proper file closure,
and cleanup when the file is no longer needed.

```python linenums="1" hl_lines="4" title="tempfile_mktemp_args_with_open_args.py"
import tempfile


filename = tempfile.NamedTemporaryFile(delete=False)
with open(
    filename, "w+", buffering=-1, encoding=None, errors=None, newline=None
) as f:
    f.write(b"Hello World!\n")
```

# See also

!!! info
    - [tempfile — Generate temporary files and directories](https://docs.python.org/3/library/tempfile.html#tempfile.mktemp)
    - [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

_New in version 0.1.9_

"""  # noqa: E501
from precli.core.call import Call
from precli.core.fix import Fix
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class MktempRaceCondition(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="insecure_temporary_file",
            description=__doc__,
            cwe_id=377,
            message="The function '{0}' can allow insecure ways of creating "
            "temporary files and directories that can lead to race "
            "conditions.",
            wildcards={
                "os.*": [
                    "open",
                ],
                "tempfile.*": [
                    "mktemp",
                ],
            },
        )

    def analyze_call(self, context: dict, call: Call) -> Result | None:
        if call.name_qualified in ["open"]:
            file_arg = call.get_argument(position=0, name="file")

            if (
                file_arg.node is not None
                and file_arg.node.type == "identifier"
                and file_arg.value == "tempfile.mktemp"
            ):
                arg_list = []
                mode = call.get_argument(position=1, name="mode").node
                mode = mode.text.decode() if mode is not None else '"r"'
                arg_list.append(f"mode={mode}")

                buff = call.get_argument(position=2, name="buffering").node
                if buff is not None:
                    arg_list.append(f"buffering={buff.text.decode()}")

                enc = call.get_argument(position=3, name="encoding").node
                if enc is not None:
                    arg_list.append(f"encoding={enc.text.decode()}")

                newline = call.get_argument(position=5, name="newline").node
                if newline is not None:
                    arg_list.append(f"newline={newline.text.decode()}")

                # mktemp(suffix='', prefix='tmp', dir=None)
                symbol = context["symtab"].get(file_arg.node.text.decode())
                init_call = symbol.call_history[0]

                suffix = init_call.get_argument(position=0, name="suffix").node
                if suffix is not None:
                    arg_list.append(f"suffix={suffix.text.decode()}")

                prefix = init_call.get_argument(position=1, name="prefix").node
                if prefix is not None:
                    arg_list.append(f"prefix={prefix.text.decode()}")

                dirs = init_call.get_argument(position=2, name="dir").node
                if dirs is not None:
                    arg_list.append(f"dir={dirs.text.decode()}")

                arg_list.append("delete=False")

                errors = call.get_argument(position=4, name="errors").node
                if errors is not None:
                    arg_list.append(f"errors={errors.text.decode()}")
                arg_str = ", ".join(arg_list)

                fixes = [
                    Fix(
                        description="Use the 'NamedTemporaryFile' class to "
                        "generate a unique filename, do proper file closure, "
                        "and cleanup.",
                        deleted_location=Location(node=init_call.node.parent),
                        inserted_content="",
                    ),
                    Fix(
                        description="Use the 'NamedTemporaryFile' class to "
                        "generate a unique filename, do proper file closure, "
                        "and cleanup.",
                        deleted_location=Location(node=call.node),
                        inserted_content=(
                            f"tempfile.NamedTemporaryFile({arg_str})"
                        ),
                    ),
                ]

                return Result(
                    rule_id=self.id,
                    location=Location(node=call.function_node),
                    message=self.message.format(file_arg.value),
                    fixes=fixes,
                )
