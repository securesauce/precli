# Copyright 2024 Secure Saurce LLC
import os

import testtools

from precli.core.artifact import Artifact
from precli.core.level import Level


class TestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()

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

    def check(self, filename):
        (
            level,
            start_line,
            end_line,
            start_column,
            end_column,
        ) = self.expected(filename)
        artifact = Artifact(os.path.join(self.base_path, filename))
        results = self.parser.parse(artifact)
        if level == Level.NONE:
            self.assertEqual(0, len(results))
        else:
            results = list(filter(lambda x: x.level != Level.NOTE, results))
            self.assertEqual(1, len(results))
            result = results[0]
            self.assertEqual(self.rule_id, result.rule_id)
            self.assertEqual(start_line, result.location.start_line)
            self.assertEqual(end_line, result.location.end_line)
            self.assertEqual(start_column, result.location.start_column)
            self.assertEqual(end_column, result.location.end_column)
            self.assertEqual(level, result.level)
            self.assertEqual(-1.0, result.rank)
