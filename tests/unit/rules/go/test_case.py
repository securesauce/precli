# Copyright 2024 Secure Saurce LLC
import os

import testtools

from precli.core.level import Level
from precli.parsers import go


class TestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = go.Go()

    def expected(self, filename):
        with open(os.path.join(self.base_path, f"{filename}.go")) as f:
            level = f.readline().strip()
            level = level.removeprefix("// level: ")
            level = getattr(Level, level)
            if level != Level.NONE:
                start_line = f.readline().strip()
                start_line = int(start_line.removeprefix("// start_line: "))
                end_line = f.readline().strip()
                end_line = int(end_line.removeprefix("// end_line: "))
                start_col = f.readline().strip()
                start_col = int(start_col.removeprefix("// start_column: "))
                end_col = f.readline().strip()
                end_col = int(end_col.removeprefix("// end_column: "))
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
        results = self.parser.parse(
            os.path.join(self.base_path, f"{filename}.go")
        )
        if level == Level.NONE:
            self.assertEqual(0, len(results))
        else:
            self.assertEqual(1, len(results))
            result = results[0]
            self.assertEqual(self.rule_id, result.rule_id)
            self.assertEqual(start_line, result.location.start_line)
            self.assertEqual(end_line, result.location.end_line)
            self.assertEqual(start_column, result.location.start_column)
            self.assertEqual(end_column, result.location.end_column)
            self.assertEqual(level, result.level)
            self.assertEqual(-1.0, result.rank)
