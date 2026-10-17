# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
from rich.padding import Padding

from precli.core.level import Level
from precli.core.run import Run
from precli.i18n import _
from precli.renderers import Renderer
from precli.rules import Rule


class Plain(Renderer):
    def file_extension(self) -> str:
        return ".txt"

    def render(self, run: Run):
        for result in run.results:
            rule = Rule.get_by_id(result.rule_id)

            style = ""
            if self.console.no_color is False:
                if result.level == Level.ERROR:
                    style = "red"
                elif result.level == Level.WARNING:
                    style = "yellow"
                elif result.level == Level.NOTE:
                    style = "blue"

            if result.artifact.uri is not None:
                file_name = result.artifact.uri
            else:
                file_name = result.artifact.file_name

            if rule:
                self.console.print(f"{rule.id}: {rule.cwe.name}")
            else:
                self.console.print(f"{result.rule_id}: Parsing error")

            # TODO(ericwb): replace hardcoded <module> with actual scope
            self.console.print(
                _(
                    f'  File "{file_name}", line '
                    f"{result.location.start_line}, in <module>",
                )
            )
            if result.snippet:
                lines = result.snippet.splitlines(keepends=True)
                code_line = lines[1] if len(lines) > 1 else lines[0]
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
            self.console.print(f"{result.message}")
            self.console.print()
        if not self.quiet:
            self.console.print(
                _(
                    f"Found {run.metrics.errors} errors, "
                    f"{run.metrics.warnings} warnings, and {run.metrics.notes}"
                    f" notes in {run.metrics.files} files and "
                    f"{run.metrics.lines} lines of code."
                )
            )
