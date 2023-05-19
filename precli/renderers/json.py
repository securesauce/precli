# Copyright 2023 Secure Saurce LLC
import json

from rich import console

from precli.core.result import Rule
from precli.renderers.renderer import Renderer


class Json(Renderer):
    def __init__(self, color: bool = False):
        super().__init__(color=color)
        self.console = console.Console(highlight=False)

    def render(self, results: list):
        for result in results:
            rule = Rule.get_by_id(result.rule_id)

            result_json = {
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

            self.console.print_json(json.dumps(result_json))
