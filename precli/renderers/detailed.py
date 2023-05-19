# Copyright 2023 Secure Saurce LLC
import linecache

from rich import console
from rich import syntax

from precli.core.level import Level
from precli.core.result import Rule
from precli.renderers.renderer import Renderer


class Detailed(Renderer):
    def __init__(self, color: bool = False):
        super().__init__(color=color)
        self.console = console.Console(highlight=False)

    def render(self, results: list):
        for result in results:
            rule = Rule.get_by_id(result.rule_id)
            match result.level:
                case Level.ERROR:
                    emoji = ":cross_mark-emoji:"
                    style = "red"

                case Level.WARNING:
                    emoji = ":warning-emoji: "
                    style = "yellow"

                case Level.NOTE:
                    emoji = ":information-emoji:"
                    style = "blue"

            self.console.print(
                f"{emoji} {result.level.name.title()} on line "
                f"{result.location.start_line} in {result.location.file_name}",
                style=style,
                markup=False,
            )
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

            for fix in result.fixes:
                self.console.print(
                    f"Suggested fix: {fix.description}",
                    style=style,
                )
                start_line = fix.deleted_location.start_line
                end_line = fix.deleted_location.end_line
                start_column = fix.deleted_location.start_column
                end_column = fix.deleted_location.end_column
                line_before = linecache.getline(
                    filename=fix.deleted_location.file_name,
                    lineno=start_line - 1,
                )
                code = linecache.getline(
                    filename=fix.deleted_location.file_name,
                    lineno=start_line,
                )
                line_after = linecache.getline(
                    filename=fix.deleted_location.file_name,
                    lineno=start_line + 1,
                )
                code = (
                    code[:start_column]
                    + fix.inserted_content
                    + code[end_column:]
                )
                code = line_before + code + line_after
                for _ in range(start_line - 2):
                    code = "\n" + code
                code = syntax.Syntax(
                    code,
                    "python",
                    line_numbers=True,
                    line_range=(start_line - 1, end_line + 1),
                    highlight_lines=(start_line, end_line),
                )
                self.console.print(code)
            self.console.print()
