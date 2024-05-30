# Copyright 2024 Secure Sauce LLC
import datetime
import io
import logging
import os
import pathlib
import sys
from functools import partial
from multiprocessing import Pool

from pygments import lexers
from rich.console import Console
from rich.progress import BarColumn
from rich.progress import MofNCompleteColumn
from rich.progress import Progress
from rich.progress import TaskProgressColumn
from rich.progress import TextColumn
from rich.progress import TimeRemainingColumn

import precli
from precli.core import loader
from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.core.location import Location
from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.core.tool import Tool
from precli.rules import Rule


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50
parsers = loader.load_parsers()


def parse_file(
    artifact: Artifact, enabled: list[str], disabled: list[str]
) -> list[Result]:
    parser = None
    results = []
    try:
        if artifact.file_name == "-":
            open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
            fdata = io.BytesIO(open_fd.read())
            artifact.file_name = "<stdin>"
            artifact.contents = fdata.read()
            lxr = lexers.guess_lexer(artifact.contents)
            artifact.language = lxr.aliases[0] if lxr.aliases else lxr.name
            parser = parsers.get(artifact.language)
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
            with open(artifact.file_name, "rb") as f:
                artifact.contents = f.read()
            return parser.parse(artifact, enabled, disabled)
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
                    start_line=e.lineno,
                    end_line=e.lineno,
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
        enabled: list[str],
        disabled: list[str],
        artifacts: list[Artifact],
        console: Console,
        debug,
    ):
        self._enabled = enabled
        self._disabled = disabled
        self._artifacts = artifacts
        self._console = console
        self._init_logger(debug)
        self._start_time = None
        self._end_time = None

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
        self._start_time = datetime.datetime.now(datetime.UTC)
        results = []
        lines = 0

        if (
            len(self._artifacts) > PROGRESS_THRESHOLD
            and LOG.getEffectiveLevel() <= logging.INFO
        ):
            parse_artifact = partial(
                parse_file, enabled=self._enabled, disabled=self._disabled
            )

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
                    results += parse_file(
                        artifact, self._enabled, self._disabled
                    )
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
        self._end_time = datetime.datetime.now(datetime.UTC)

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
    def metrics(self) -> list[Result]:
        """Get the list of results."""
        return self._metrics
