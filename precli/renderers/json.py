# Copyright 2024 Secure Saurce LLC
import json

from rich import console

from precli.core.run import Run
from precli.renderers import Renderer
from precli.rules import Rule


class Json(Renderer):
    def __init__(self, no_color: bool = False):
        super().__init__(no_color=no_color)
        self.console = console.Console(highlight=False)

    def render(self, run: Run):
        results_json = {"results": []}
        for result in run.results:
            rule = Rule.get_by_id(result.rule_id)

            if result.artifact.uri is not None:
                file_name = result.artifact.uri
            else:
                file_name = result.artifact.file_name

            results_json["results"].append(
                {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "cwe_id": rule.cwe.cwe_id,
                    "severity": result.level.name,
                    "file_name": file_name,
                    "start_line": result.location.start_line,
                    "end_line": result.location.end_line,
                    "start_column": result.location.start_column,
                    "end_column": result.location.end_column,
                    "message": result.message,
                    "rank": result.rank,
                    "help_url": rule.help_url,
                }
            )
        results_json["metrics"] = {
            "files": run.metrics.files,
            "files_skipped": run.metrics.files_skipped,
            "lines": run.metrics.lines,
            "errors": run.metrics.errors,
            "warnings": run.metrics.warnings,
            "notes": run.metrics.notes,
        }
        self.console.print_json(json.dumps(results_json))
