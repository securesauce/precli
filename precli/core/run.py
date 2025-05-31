# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import datetime
import io
import logging
import os
import pathlib
import sys
from functools import partial
from multiprocessing import Pool
from typing import Optional

from rich.progress import BarColumn
from rich.progress import MofNCompleteColumn
from rich.progress import Progress
from rich.progress import TaskProgressColumn
from rich.progress import TextColumn
from rich.progress import TimeRemainingColumn

import precli
from precli.core import loader
from precli.core.artifact import Artifact
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.core.tool import Tool
from precli.parsers.basic import Basic
from precli.rules import Rule


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50
parsers = loader.load_extension(group="precli.parsers")


def parse_file(artifact: Artifact, config: dict) -> list[Result]:
    parser = None
    results = []
    try:
        if artifact.file_name == "-":
            open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
            fdata = io.BytesIO(open_fd.read())
            artifact.file_name = "<stdin>"
            artifact.contents = fdata.read()

            for p in parsers.values():
                if p.is_valid_code(artifact.contents):
                    artifact.language = p.lexer
                    parser = p
                    break
        else:
            file_extension = pathlib.Path(artifact.file_name).suffix
            parser = next(
                (
                    p
                    for p in parsers.values()
                    if file_extension in p.file_extensions()
                ),
                None,
            )

        if parser:
            LOG.debug(f"Working on file: {artifact.file_name}")
            artifact.language = parser.lexer
            if artifact.contents is None:
                with open(artifact.file_name, "rb") as f:
                    artifact.contents = f.read()
            return parser.parse(artifact, config)
    except OSError as e:
        results.append(
            Result(
                f"{parser.rule_prefix()}000" if parser else "NO_RULE",
                location=Location(parser.context["node"]),
                artifact=artifact,
                level=Level.ERROR,
                message=e.strerror,
            )
        )
    except SyntaxError as e:
        results.append(
            Result(
                f"{parser.rule_prefix()}000" if parser else "NO_RULE",
                location=Location(
                    start_line=e.lineno if e.lineno else 0,
                    end_line=e.lineno if e.lineno else 0,
                ),
                artifact=artifact,
                level=Level.ERROR,
                message="Syntax error while parsing file.",
            )
        )
    except UnicodeDecodeError:
        results.append(
            Result(
                f"{parser.rule_prefix()}000" if parser else "NO_RULE",
                location=Location(parser.context["node"]),
                artifact=artifact,
                level=Level.ERROR,
                message="Invalid unicode character while parsing file.",
            )
        )
    except Exception as e:
        results.append(
            Result(
                f"{parser.rule_prefix()}000" if parser else "NO_RULE",
                location=Location(parser.context["node"]),
                artifact=artifact,
                level=Level.ERROR,
                message=": ".join([type(e).__name__, str(e)]),
            )
        )
    return results


class Run:
    def __init__(
        self,
        config: dict,
        artifacts: list[Artifact],
        debug: int,
        custom_rules: Optional[list[dict]] = None,
    ):
        self._config = config
        self._artifacts = artifacts
        self._init_logger(debug)
        self._start_time = None
        self._end_time = None

        if custom_rules:
            for custom_rule in custom_rules:
                if custom_rule["language"] not in parsers:
                    parsers[custom_rule["language"]] = Basic(
                        custom_rule["language"]
                    )
                parser = parsers[custom_rule["language"]]

                default_config = Config()
                default_config.level = Level(
                    custom_rule.get("severity", Level.WARNING)
                )
                rule = Rule(
                    id=custom_rule["id"],
                    name=custom_rule["name"],
                    description=custom_rule["description"],
                    cwe_id=custom_rule["cwe"],
                    message=custom_rule["message"],
                    config=default_config,
                    query=custom_rule["query"],
                    location_node=custom_rule["location_node"],
                )
                parser.rules[rule.name] = rule

    def _init_logger(self, log_level=logging.INFO):
        """Initialize the logger.

        :param debug: Whether to enable debug mode
        :return: An instantiated logging instance
        """
        LOG.handlers = []
        logging.captureWarnings(True)
        LOG.setLevel(log_level)
        handler = logging.StreamHandler(sys.stderr)
        LOG.addHandler(handler)
        LOG.debug("logging initialized")

        self._tool = Tool(
            name="Precaution",
            download_uri=precli.__download_url__,
            full_description=precli.__summary__,
            information_uri=precli.__url__,
            organization=precli.__author__,
            short_description=precli.__summary__,
            version=precli.__version__,
        )

    @property
    def tool(self) -> Tool:
        """Get the tool associated with this run."""
        return self._tool

    @property
    def rules(self) -> list[Rule]:
        """Set of supported rules."""
        return [r for p in parsers.values() for r in p.rules.values()]

    def invoke(self):
        """Invokes a run"""
        if sys.version_info >= (3, 11):
            self._start_time = datetime.datetime.now(datetime.UTC)
        else:
            self._start_time = datetime.datetime.utcnow()
        LOG.debug(f"Run started at {self._start_time}")
        results = []
        lines = 0

        if (
            len(self._artifacts) > PROGRESS_THRESHOLD
            and LOG.getEffectiveLevel() <= logging.INFO
        ):
            parse_artifact = partial(parse_file, config=self._config)

            progress = Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
            )

            with progress:
                task_id = progress.add_task(
                    "Analyzing...", total=len(self._artifacts)
                )

                with Pool(processes=None) as pool:
                    try:
                        for res in pool.imap(parse_artifact, self._artifacts):
                            results += res
                            progress.advance(task_id)
                    except KeyboardInterrupt:
                        sys.exit(2)
        else:
            for artifact in self._artifacts:
                if artifact.file_name != "-":
                    with open(artifact.file_name, "rb") as f:
                        lines += sum(1 for _ in f)
                try:
                    results += parse_file(artifact, self._config)
                except KeyboardInterrupt:
                    sys.exit(2)

        self._metrics = Metrics(
            files=len(self._artifacts),
            lines=lines,
            errors=sum(result.level == Level.ERROR for result in results),
            warnings=sum(result.level == Level.WARNING for result in results),
            notes=sum(result.level == Level.NOTE for result in results),
        )
        self._results = results

        if sys.version_info >= (3, 11):
            self._end_time = datetime.datetime.now(datetime.UTC)
        else:
            self._end_time = datetime.datetime.utcnow()
        LOG.debug(f"Run ended at {self._end_time}")

    @property
    def start_time(self):
        return self._start_time

    @property
    def end_time(self):
        return self._end_time

    @property
    def results(self) -> list[Result]:
        """Get the list of results."""
        return self._results

    @property
    def metrics(self) -> Metrics:
        """Get the list of results."""
        return self._metrics
