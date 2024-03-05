# Copyright 2024 Secure Saurce LLC
import pathlib
import sys
import urllib.parse as urlparse
from datetime import datetime

import sarif_om
from jschema_to_python.to_json import to_json

from precli.core.fix import Fix
from precli.core.run import Run
from precli.renderers import Renderer


SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Json(Renderer):
    def __init__(self, file: sys.stdout, no_color: bool = False):
        super().__init__(file=file, no_color=no_color)

    def to_uri(self, file):
        path = pathlib.PurePath(file)
        if path.is_absolute():
            return path.as_uri()
        else:
            posix = path.as_posix()
            return urlparse.quote(posix)

    def to_fix(self, file_name: str, fix: Fix):
        return sarif_om.Fix(
            artifact_changes=[
                sarif_om.ArtifactChange(
                    artifact_location=sarif_om.ArtifactLocation(
                        uri=self.to_uri(file_name)
                    ),
                    replacements=[
                        sarif_om.Replacement(
                            deleted_region=sarif_om.Region(
                                start_line=fix.deleted_location.start_line,
                                end_line=fix.deleted_location.end_line,
                                start_column=fix.deleted_location.start_column
                                + 1,
                                end_column=fix.deleted_location.end_column + 1,
                            ),
                            inserted_content=sarif_om.ArtifactContent(
                                text=fix.inserted_content,
                            ),
                        ),
                    ],
                )
            ],
            description=sarif_om.Message(text=fix.description),
        )

    def create_rule_array(self, run: Run):
        rules = []

        for rule in run.tool.rules:
            reporting_descriptor = sarif_om.ReportingDescriptor(
                id=rule.id,
                name=rule.__class__.__name__,
                help_uri=rule.help_url,
                message_strings={
                    "default": sarif_om.MultiformatMessageString(
                        text=rule.message
                    )
                },
                properties={
                    "tags": ["security"],
                },
            )
            rules.append(reporting_descriptor)

        return rules

    def create_tool_component(self, run: Run):
        return sarif_om.ToolComponent(
            name=run.tool.name,
            download_uri=run.tool.download_uri,
            full_description=sarif_om.MultiformatMessageString(
                text=run.tool.full_description
            ),
            information_uri=run.tool.information_uri,
            organization=run.tool.organization,
            semantic_version=run.tool.version,
            short_description=sarif_om.MultiformatMessageString(
                text=run.tool.short_description
            ),
            version=run.tool.version,
            rules=self.create_rule_array(run),
        )

    def render(self, run: Run):
        log = sarif_om.SarifLog(
            schema_uri=SCHEMA_URI,
            version="2.1.0",
            runs=[
                sarif_om.Run(
                    tool=sarif_om.Tool(driver=self.create_tool_component(run)),
                    invocations=[
                        sarif_om.Invocation(
                            end_time_utc=datetime.utcnow().strftime(TS_FORMAT),
                            execution_successful=True,
                        )
                    ],
                )
            ],
        )

        sarif_run = log.runs[0]
        sarif_run.results = []

        for result in run.results:
            fixes = []
            for fix in result.fixes:
                fixes.append(self.to_fix(result.artifact.file_name, fix))

            physical_location = sarif_om.PhysicalLocation(
                artifact_location=sarif_om.ArtifactLocation(
                    uri=self.to_uri(result.artifact.file_name)
                )
            )

            code_lines = result.snippet.splitlines(keepends=True)
            code_line = code_lines[1] if len(code_lines) > 1 else code_lines[0]
            physical_location.region = sarif_om.Region(
                start_line=result.location.start_line,
                end_line=result.location.end_line,
                start_column=result.location.start_column + 1,
                end_column=result.location.end_column + 1,
                snippet=sarif_om.ArtifactContent(text=code_line),
            )

            physical_location.context_region = sarif_om.Region(
                start_line=result.location.start_line - 1,
                end_line=result.location.end_line + 1,
                snippet=sarif_om.ArtifactContent(text=result.snippet),
            )

            sarif_result = sarif_om.Result(
                message=sarif_om.Message(text=result.message),
                fixes=fixes,
                level=result.level.name.lower(),
                locations=[
                    sarif_om.Location(physical_location=physical_location),
                ],
                rule_id=result.rule_id,
            )

            sarif_run.results.append(sarif_result)
        self.console.print_json(to_json(log))
