# Copyright 2023 Secure Saurce LLC
import linecache

from rich import console
from rich.padding import Padding

from precli.core.level import Level
from precli.core.result import Rule
from precli.renderers.renderer import Renderer


class Plain(Renderer):
    def __init__(self, color: bool = False):
        super().__init__(color=color)
        self.console = console.Console(highlight=False)

    def render(self, results: list):
        for result in results:
            rule = Rule.get_by_id(result.rule_id)

            if self._color is True:
                match result.level:
                    case Level.ERROR:
                        style = "red"

                    case Level.WARNING:
                        style = "yellow"

                    case Level.NOTE:
                        style = "blue"
            else:
                style = ""

            self.console.print(
                f"{rule.id}: {rule.cwe.name}",
                style=style,
            )
            self.console.print(
                f'  File "{result.location.file_name}", line '
                f"{result.location.start_line}, in <module>",
                style=style,
            )
            code_line = linecache.getline(
                filename=result.location.file_name,
                lineno=result.location.start_line,
            ).rstrip()
            self.console.print(
                Padding(code_line, (0, 4)),
                style=style,
            )
            underline_width = (
                result.location.end_column - result.location.start_column
            )
            underline = "^" * underline_width
            self.console.print(
                Padding(underline, (0, result.location.start_column + 4)),
                style=style,
            )
            self.console.print(
                f"{result.level.name.title()}: {result.message}",
                style=style,
            )
            self.console.print()
