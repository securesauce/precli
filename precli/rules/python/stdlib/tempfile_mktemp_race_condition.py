# Copyright 2024 Secure Saurce LLC
r"""
==============================================
Insecure Temporary File in the Tempfile Module
==============================================

The tempfile.mktemp function in Python is a legacy method for creating
temporary files with a unique name. It is important to note that this function
is susceptible to race conditions, which can occur when multiple processes or
threads attempt to create temporary files concurrently. These race conditions
may lead to unintended behavior, data corruption, or security vulnerabilities
in your code.

-------
Example
-------

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import tempfile


    filename = tempfile.mktemp(suffix='', prefix='tmp', dir=None)
    with open(filename) as f:
        f.write(b"Hello World!\n")

-----------
Remediation
-----------

To ensure the reliability and security of your temporary file management,
consider using NamedTemporaryFile. The tempfile.NamedTemporaryFile class
automatically handles the generation of unique filenames, proper file closure,
and cleanup when the file is no longer needed.

.. code-block:: python
   :linenos:
   :emphasize-lines: 4

    import tempfile


    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"Hello World!\n")

.. seealso::

 - `tempfile — Generate temporary files and directories <https://docs.python.org/3/library/tempfile.html#tempfile.mktemp>`_
 - `CWE-377: Insecure Temporary File <https://cwe.mitre.org/data/definitions/377.html>`_

.. versionadded:: 0.1.9

"""  # noqa: E501
from precli.core.fix import Fix
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class MktempRaceCondition(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="insecure_temporary_file",
            full_descr=__doc__,
            cwe_id=377,
            message="The function '{}' can allow insecure ways of creating "
            "temporary files and directories that can lead to race "
            "conditions.",
            targets=("call"),
            wildcards={
                "os.*": [
                    "open",
                ],
                "tempfile.*": [
                    "mktemp",
                ],
            },
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["open"]:
            file_arg = call.get_argument(position=0, name="file")

            if (
                file_arg.node is not None
                and file_arg.node.type == "identifier"
                and file_arg.value == "tempfile.mktemp"
            ):
                """
                open(
                    file,
                    mode='r',
                    buffering=-1,
                    encoding=None,
                    errors=None,
                    newline=None,
                    closefd=True,
                    opener=None
                )
                """
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

                """
                NamedTemporaryFile(
                    mode='w+b',
                    buffering=-1,
                    encoding=None,
                    newline=None,
                    suffix=None,
                    prefix=None,
                    dir=None,
                    delete=True,
                    *,
                    errors=None
                )
                """
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
