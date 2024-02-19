# Copyright 2024 Secure Saurce LLC
import sys

from rich.padding import Padding

from precli.core.level import Level
from precli.core.run import Run
from precli.renderers import Renderer
from precli.rules import Rule


class Plain(Renderer):
    def __init__(self, file: sys.stdout, no_color: bool = False):
        super().__init__(file=file, no_color=no_color)

    def render(self, run: Run):
        for result in run.results:
            rule = Rule.get_by_id(result.rule_id)

            if self._no_color is True:
                style = ""
            else:
                match result.level:
                    case Level.ERROR:
                        style = "red"

                    case Level.WARNING:
                        style = "yellow"

                    case Level.NOTE:
                        style = "blue"

            if result.artifact.uri is not None:
                file_name = result.artifact.uri
            else:
                file_name = result.artifact.file_name

            self.console.print(
                f"{rule.id}: {rule.cwe.name}",
            )

            # TODO(ericwb): replace hardcoded <module> with actual scope
            self.console.print(
                f'  File "{file_name}", line '
                f"{result.location.start_line}, in <module>",
            )
            code_lines = result.snippet.splitlines(keepends=True)
            code_line = code_lines[1] if len(code_lines) > 1 else code_lines[0]
            underline_width = (
                result.location.end_column - result.location.start_column
            )
            underline = (
                " " * result.location.start_column + "^" * underline_width
            )
            self.console.print(
                Padding(code_line + underline, (0, 4)),
            )
            self.console.print(
                f"{result.level.name.title()}: ",
                style=style,
                end="",
            )
            self.console.print(
                f"{result.message}",
            )
            self.console.print()
        self.console.print(
            f"Found {run.metrics.errors} errors, {run.metrics.warnings} "
            f"warnings, and {run.metrics.notes} notes in "
            f"{run.metrics.files} files and {run.metrics.lines} lines of "
            f"code."
        )
