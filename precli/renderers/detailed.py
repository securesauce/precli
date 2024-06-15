# Copyright 2024 Secure Sauce LLC
from rich import box
from rich import syntax
from rich.table import Table

from precli.core.level import Level
from precli.core.linecache import LineCache
from precli.core.run import Run
from precli.renderers import Renderer
from precli.rules import Rule


class Detailed(Renderer):
    def render(self, run: Run):
        for result in run.results:
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

            if result.artifact.uri is not None:
                if result.location.start_line != result.location.end_line:
                    lines = (
                        f"L{result.location.start_line}-"
                        f"L{result.location.end_line}"
                    )
                else:
                    lines = f"L{result.location.start_line}"
                file_name = f"{result.artifact.uri}#{lines}"
            else:
                file_name = result.artifact.file_name

            self.console.print(
                f"{emoji} {result.level.name.title()} on line "
                f"{result.location.start_line} in {file_name}",
                style=style,
                markup=False,
            )
            rule = Rule.get_by_id(result.rule_id)
            if rule:
                self.console.print(f"{rule.id}: {rule.cwe.name}", style=style)
            else:
                self.console.print(
                    f"{result.rule_id}: Parsing error", style=style
                )
            self.console.print(f"{result.message}", style=style)

            line_offset = result.location.start_line - 2
            code = syntax.Syntax(
                result.snippet,
                result.artifact.language,
                line_numbers=True,
                start_line=line_offset + 1,
                line_range=(
                    result.location.start_line - line_offset - 1,
                    result.location.end_line - line_offset + 1,
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

                linecache = LineCache(
                    result.artifact.file_name,
                    result.artifact.contents.decode(),
                )

                if (start_line - 1) in highlight_lines:
                    line_before = ""
                    before = 0
                else:
                    line_before = linecache.getline(lineno=start_line - 1)
                    before = 1

                code = linecache.getline(lineno=start_line)

                if (start_line + 1) in highlight_lines:
                    line_after = ""
                    after = 0
                else:
                    line_after = linecache.getline(lineno=start_line + 1)
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
                    result.artifact.language,
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
            f"{run.metrics.files:,}",
            "Lines analyzed",
            f"{run.metrics.lines:,}",
            end_section=True,
        )
        table.add_row(
            "Errors",
            f"{run.metrics.errors:,}",
            style="red" if run.metrics.errors else "",
        )
        table.add_row(
            "Warnings",
            f"{run.metrics.warnings:,}",
            style="yellow" if run.metrics.warnings else "",
        )
        table.add_row(
            "Notes",
            f"{run.metrics.notes:,}",
            style="blue" if run.metrics.notes else "",
        )
        self.console.print(table)
