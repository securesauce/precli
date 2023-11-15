# Copyright 2023 Secure Saurce LLC
import linecache

from rich import box
from rich import console
from rich import syntax
from rich.table import Table

from precli.core.level import Level
from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.renderers import Renderer
from precli.rules import Rule


class Detailed(Renderer):
    def __init__(self, no_color: bool = False):
        super().__init__(no_color=no_color)
        if no_color is True:
            self.console = console.Console(color_system=None, highlight=False)
        else:
            self.console = console.Console(highlight=False)

    def render(self, results: list[Result], metrics: Metrics):
        for result in results:
            match result.level:
                case Level.ERROR:
                    emoji = ":no_entry-emoji:"
                    style = "red"

                case Level.WARNING:
                    emoji = ":warning-emoji: "
                    style = "yellow"

                case Level.NOTE:
                    emoji = ":information-emoji: "
                    style = "blue"

            self.console.print(
                f"{emoji} {result.level.name.title()} on line "
                f"{result.location.start_line} in {result.location.file_name}",
                style=style,
                markup=False,
            )
            rule = Rule.get_by_id(result.rule_id)
            self.console.print(
                f"{rule.id}: {rule.cwe.name}",
                style=style,
            )
            self.console.print(
                f"{result.message}",
                style=style,
            )
            code = syntax.Syntax.from_path(
                result.location.file_name,
                line_numbers=True,
                line_range=(
                    result.location.start_line - 1,
                    result.location.end_line + 1,
                ),
                highlight_lines=(
                    result.location.start_line,
                    result.location.end_line,
                ),
            )
            self.console.print(code)

            if result.fixes:
                self.console.print(
                    f"Suggested fix: {result.fixes[0].description}",
                    style=style,
                )

            highlight_lines = set()
            for fix in result.fixes:
                highlight_lines.add(fix.deleted_location.start_line)
                highlight_lines.add(fix.deleted_location.end_line)

            for fix in result.fixes:
                start_line = fix.deleted_location.start_line
                end_line = fix.deleted_location.end_line
                start_column = fix.deleted_location.start_column
                end_column = fix.deleted_location.end_column

                if (start_line - 1) in highlight_lines:
                    line_before = ""
                    before = 0
                else:
                    line_before = linecache.getline(
                        filename=result.location.file_name,
                        lineno=start_line - 1,
                    )
                    before = 1

                code = linecache.getline(
                    filename=result.location.file_name,
                    lineno=start_line,
                )

                if (start_line + 1) in highlight_lines:
                    line_after = ""
                    after = 0
                else:
                    line_after = linecache.getline(
                        filename=result.location.file_name,
                        lineno=start_line + 1,
                    )
                    after = 1

                code = (
                    code[:start_column]
                    + fix.inserted_content
                    + code[end_column:]
                )
                code = line_before + code + line_after
                for _ in range(start_line - 1 - before):
                    code = "\n" + code

                code = syntax.Syntax(
                    code,
                    "python",
                    line_numbers=True,
                    line_range=(start_line - before, end_line + after),
                    highlight_lines=highlight_lines,
                )
                self.console.print(code)
            self.console.print()

        # Print the summary
        table = Table(
            box=box.HEAVY,
            min_width=60,
            show_header=False,
        )
        table.add_column(justify="left")
        table.add_column(justify="right")
        table.add_column(justify="left")
        table.add_column(justify="right")
        table.add_row(
            "Files analyzed",
            f"{metrics.files:,}",
            "Lines analyzed",
            f"{metrics.lines:,}",
        )
        table.add_row(
            "Files skipped",
            f"{metrics.files_skipped:,}",
            end_section=True,
        )
        table.add_row(
            "Errors",
            f"{metrics.errors:,}",
            style="red" if metrics.errors else "",
        )
        table.add_row(
            "Warnings",
            f"{metrics.warnings:,}",
            style="yellow" if metrics.warnings else "",
        )
        table.add_row(
            "Notes",
            f"{metrics.notes:,}",
            style="blue" if metrics.notes else "",
        )
        self.console.print(table)
