# Copyright 2023 Secure Saurce LLC
import json

from rich import console

from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.renderers import Renderer
from precli.rules import Rule


class Json(Renderer):
    def __init__(self, no_color: bool = False):
        super().__init__(no_color=no_color)
        self.console = console.Console(highlight=False)

    def render(self, results: list[Result], metrics: Metrics):
        results_json = {"results": []}
        for result in results:
            rule = Rule.get_by_id(result.rule_id)

            results_json["results"].append(
                {
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "cwe_id": rule.cwe.cwe_id,
                    "severity": result.level.name,
                    "file_name": result.location.file_name,
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
            "files": metrics.files,
            "files_skipped": metrics.files_skipped,
            "lines": metrics.lines,
            "errors": metrics.errors,
            "warnings": metrics.warnings,
            "notes": metrics.notes,
        }
        self.console.print_json(json.dumps(results_json))
