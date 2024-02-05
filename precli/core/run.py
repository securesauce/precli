# Copyright 2024 Secure Saurce LLC
import io
import logging
import os
import sys
import traceback

from pygments import lexers
from rich import progress
from rich import syntax

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.core.tool import Tool


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50


class Run:
    def __init__(
        self, tool: Tool, parsers: dict, artifacts: list[Artifact], debug
    ):
        self._tool = tool
        self._parsers = parsers
        self._artifacts = artifacts
        self._init_logger(debug)

    def _init_logger(self, log_level=logging.INFO):
        """Initialize the logger.

        :param debug: Whether to enable debug mode
        :return: An instantiated logging instance
        """
        LOG.handlers = []
        logging.captureWarnings(True)
        LOG.setLevel(log_level)
        logging.getLogger("urllib3").setLevel(log_level)
        handler = logging.StreamHandler(sys.stderr)
        LOG.addHandler(handler)
        LOG.debug("logging initialized")

    @property
    def tool(self) -> Tool:
        """
        Get the tool associated with this run.

        :return: tool object
        :rtype: Tool
        """
        return self._tool

    def invoke(self):
        """Invokes a run"""
        # if we have problems with a file, we'll remove it from the file_list
        # and add it to the skipped list instead
        new_artifacts = list(self._artifacts)
        files_skipped = []
        if (
            len(self._artifacts) > PROGRESS_THRESHOLD
            and LOG.getEffectiveLevel() <= logging.INFO
        ):
            artifacts = progress.track(self._artifacts)
        else:
            artifacts = self._artifacts

        results = []
        lines = 0
        for artifact in artifacts:
            try:
                if artifact.file_name == "-":
                    open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
                    fdata = io.BytesIO(open_fd.read())
                    artifact.file_name = "<stdin>"
                    artifact.contents = fdata.read()
                else:
                    with open(artifact.file_name, "rb") as fdata:
                        lines += sum(1 for _ in fdata)
                    with open(artifact.file_name, "rb") as fdata:
                        artifact.contents = fdata.read()
                results += self.parse_file(
                    artifact, new_artifacts, files_skipped
                )
            except OSError as e:
                files_skipped.append((artifact.file_name, e.strerror))
                new_artifacts.remove(artifact)

        self._metrics = Metrics(
            files=len(new_artifacts),
            files_skipped=len(files_skipped),
            lines=lines,
            errors=sum(result.level == Level.ERROR for result in results),
            warnings=sum(result.level == Level.WARNING for result in results),
            notes=sum(result.level == Level.NOTE for result in results),
        )
        self._results = results

    def parse_file(
        self,
        artifact: Artifact,
        new_artifacts: list,
        files_skipped: list,
    ) -> list[Result]:
        try:
            artifact.language = syntax.Syntax.guess_lexer(
                artifact.file_name, artifact.contents
            )
            if artifact.language == "default":
                lxr = lexers.guess_lexer(artifact.contents)
                artifact.language = lxr.aliases[0] if lxr.aliases else lxr.name

            if artifact.language in self._parsers.keys():
                LOG.debug("working on file : %s", artifact.file_name)
                parser = self._parsers[artifact.language]
                return parser.parse(artifact)
        except KeyboardInterrupt:
            sys.exit(2)
        except SyntaxError as e:
            print(
                f"Syntax error while parsing file. ({e.filename}, "
                f"line {e.lineno})",
                file=sys.stderr,
            )
            files_skipped.append((artifact.file_name, e))
            new_artifacts.remove(artifact)
        except Exception as e:
            LOG.error(
                f"Exception occurred when executing rules against "
                f'{artifact.file_name}. Run "precli --debug '
                f'{artifact.file_name}" to see the full traceback.'
            )
            files_skipped.append(
                (artifact.file_name, "Exception while parsing file")
            )
            new_artifacts.remove(artifact)
            LOG.debug(f"  Exception string: {e}")
            LOG.debug(f"  Exception traceback: {traceback.format_exc()}")
        return []

    @property
    def results(self) -> list[Result]:
        """
        Get the list of results.

        :return: list of results
        :rtype: list
        """
        return self._results

    @property
    def metrics(self) -> list[Result]:
        """
        Get the list of results.

        :return: list of results
        :rtype: list
        """
        return self._metrics
