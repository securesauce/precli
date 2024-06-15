# Copyright 2024 Secure Sauce LLC
import logging
import sys

from rich import markdown

from precli.core.level import Level
from precli.core.linecache import LineCache
from precli.core.run import Run
from precli.renderers import Renderer
from precli.rules import Rule


logging.getLogger("markdown_it").setLevel(logging.INFO)


class Markdown(Renderer):
    def render(self, run: Run):
        output = ""
        for result in run.results:
            rule = Rule.get_by_id(result.rule_id)

            try:
                linecache = LineCache(
                    result.artifact.file_name,
                    result.artifact.contents.decode(result.artifact.encoding),
                )
            except UnicodeDecodeError:
                pass

            match result.level:
                case Level.ERROR:
                    alert = "CAUTION"
                case Level.WARNING:
                    alert = "WARNING"
                case Level.NOTE:
                    alert = "NOTE"

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

            if rule:
                output += (
                    f"> [!{alert}]\n"
                    f">\n"
                    f"> [{rule.id}]({rule.help_url}): {rule.cwe.name}\n"
                    f"on line {result.location.start_line} in {file_name}\n"
                    f"> \n"
                    f"> {result.message}\n"
                )
            else:
                output += (
                    f"> [!{alert}]\n"
                    f">\n"
                    f"> {result.rule_id}: Parsing error\n"
                    f"on line {result.location.start_line} in {file_name}\n"
                    f"> \n"
                    f"> {result.message}\n"
                )

            if result.snippet:
                output += f"> ```{result.artifact.language}\n"
                output += f"{result.snippet}"
                output += "> ```\n"

            if result.fixes:
                output += f"> Suggested fix: {result.fixes[0].description}\n"

            for fix in result.fixes:
                start_line = fix.deleted_location.start_line
                start_column = fix.deleted_location.start_column
                end_column = fix.deleted_location.end_column

                code = linecache.getline(lineno=start_line)
                code = (
                    code[:start_column]
                    + fix.inserted_content
                    + code[end_column:]
                )
                output += f"> ```{result.artifact.language}\n"
                for line in code.splitlines():
                    output += f"> {line}\n"
                output += "> ```\n"
            output += "\n"

        output += (
            f"| Metric | Value |\n"
            f"| --- | --- |\n"
            f"| Files analyzed | {run.metrics.files:,} |\n"
            f"| Lines analyzed | {run.metrics.lines:,} |\n"
            f"| Errors | {run.metrics.errors:,} |\n"
            f"| Warnings | {run.metrics.warnings:,} |\n"
            f"| Notes | {run.metrics.notes:,} |\n"
        )

        if self.console.file.name != sys.stdout.name:
            self.console.print(output, soft_wrap=True)
        else:
            md = markdown.Markdown(output)
            self.console.print(md, soft_wrap=True)
