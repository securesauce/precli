# Copyright 2024 Secure Sauce LLC
import os

from precli.core.artifact import Artifact
from precli.core.level import Level


class TestCase:
    def expected(self, filename):
        with open(os.path.join(self.base_path, filename)) as f:
            level = f.readline().strip()
            level = level.lstrip("/# ").removeprefix("level: ")
            level = getattr(Level, level)
            if level != Level.NONE:
                start_line = f.readline().strip()
                start_line = int(
                    start_line.lstrip("/# ").removeprefix("start_line: ")
                )
                end_line = f.readline().strip()
                end_line = int(
                    end_line.lstrip("/# ").removeprefix("end_line: ")
                )
                start_col = f.readline().strip()
                start_col = int(
                    start_col.lstrip("/# ").removeprefix("start_column: ")
                )
                end_col = f.readline().strip()
                end_col = int(
                    end_col.lstrip("/# ").removeprefix("end_column: ")
                )
            else:
                start_line = end_line = start_col = end_col = -1

        return (level, start_line, end_line, start_col, end_col)

    def check(self, filename, enabled=None, disabled=None):
        (
            level,
            start_line,
            end_line,
            start_column,
            end_column,
        ) = self.expected(filename)
        artifact = Artifact(os.path.join(self.base_path, filename))
        results = self.parser.parse(artifact, enabled, disabled)
        if level == Level.NONE:
            assert len(results) == 0
        else:
            results = list(filter(lambda x: x.level != Level.NOTE, results))
            assert len(results) == 1
            result = results[0]
            assert result.rule_id == self.rule_id
            assert result.location.start_line == start_line
            assert result.location.end_line == end_line
            assert result.location.start_column == start_column
            assert result.location.end_column == end_column
            assert result.level == level
            assert result.rank == -1.0
