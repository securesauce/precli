# Copyright 2024 Secure Sauce LLC
import pathlib
import urllib.parse as urlparse
from importlib import metadata

import sarif_om
from jschema_to_python.to_json import to_json

from precli.core.fix import Fix
from precli.core.result import Result
from precli.core.run import Run
from precli.renderers import Renderer
from precli.rules import Rule


SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SCHEMA_VER = "2.1.0"
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class Json(Renderer):
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

    def create_rule_if_needed(
        self, result: Result, rules: dict, rule_indices: dict
    ):
        rule = Rule.get_by_id(result.rule_id)
        if not rule:
            return None, -1

        if rule.id in rules:
            return rules[rule.id], rule_indices[rule.id]

        reporting_descriptor = sarif_om.ReportingDescriptor(
            id=rule.id,
            name=rule.__class__.__name__,
            help_uri=rule.help_url,
            short_description=sarif_om.MultiformatMessageString(
                text=rule.short_description
            ),
            default_configuration=sarif_om.ReportingConfiguration(
                enabled=rule.default_config.enabled,
                level=rule.default_config.level.name.lower(),
            ),
            help=sarif_om.MultiformatMessageString(
                text=rule.full_description, markdown=rule.full_description
            ),
            message_strings={
                "default": sarif_om.MultiformatMessageString(text=rule.message)
            },
            properties={
                "tags": [
                    "security",
                    f"external/cwe/cwe-{rule.cwe.id}",
                ],
                "security-severity": (rule.default_config.level.to_severity()),
            },
        )

        index = len(rules)
        rules[rule.id] = reporting_descriptor
        rule_indices[rule.id] = index

        return reporting_descriptor, index

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
        )

    def get_extensions(self) -> list:
        precli_exts = []
        for dist in metadata.distributions():
            if dist.name.startswith("precli-"):
                precli_exts.append(
                    sarif_om.ToolComponent(
                        name=dist.name,
                        organization=dist.metadata["Author"],
                        semantic_version=dist.version,
                        short_description=sarif_om.MultiformatMessageString(
                            text=dist.metadata["Summary"]
                        ),
                    )
                )
        return precli_exts

    def render(self, run: Run):
        log = sarif_om.SarifLog(
            schema_uri=SCHEMA_URI,
            version=SCHEMA_VER,
            runs=[
                sarif_om.Run(
                    tool=sarif_om.Tool(
                        driver=self.create_tool_component(run),
                        extensions=self.get_extensions(),
                    ),
                    invocations=[
                        sarif_om.Invocation(
                            start_time_utc=run.start_time.strftime(TS_FORMAT),
                            end_time_utc=run.end_time.strftime(TS_FORMAT),
                            execution_successful=True,
                        )
                    ],
                )
            ],
        )

        sarif_run = log.runs[0]
        sarif_run.results = []

        rules = {}
        rule_indices = {}

        for result in run.results:
            _, rule_index = self.create_rule_if_needed(
                result, rules, rule_indices
            )

            fixes = []
            for fix in result.fixes:
                fixes.append(self.to_fix(result.artifact.file_name, fix))

            physical_location = sarif_om.PhysicalLocation(
                artifact_location=sarif_om.ArtifactLocation(
                    uri=self.to_uri(result.artifact.file_name)
                )
            )

            physical_location.region = sarif_om.Region(
                start_line=result.location.start_line,
                end_line=result.location.end_line,
                start_column=result.location.start_column + 1,
                end_column=result.location.end_column + 1,
            )

            if result.snippet:
                lines = result.snippet.splitlines(keepends=True)
                code_line = lines[1] if len(lines) > 1 else lines[0]
                physical_location.region.snippet = sarif_om.ArtifactContent(
                    text=code_line
                )

                physical_location.context_region = sarif_om.Region(
                    start_line=result.location.start_line - 1,
                    end_line=result.location.end_line + 1,
                    snippet=sarif_om.ArtifactContent(text=result.snippet),
                )

            sarif_result = sarif_om.Result(
                rule_id=result.rule_id,
                rule_index=rule_index,
                message=sarif_om.Message(text=result.message),
                fixes=fixes,
                level=result.level.name.lower(),
                locations=[
                    sarif_om.Location(physical_location=physical_location),
                ],
            )

            sarif_run.results.append(sarif_result)

        if rules:
            sarif_run.tool.driver.rules = list(rules.values())

        self.console.print_json(to_json(log))
