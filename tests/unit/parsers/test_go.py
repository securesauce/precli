# Copyright 2024 Secure Saurce LLC
import os

import testtools

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.parsers import go


class TestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.parser = go.Go()
        self.base_path = os.path.join(
            "tests",
            "unit",
            "parsers",
            "examples",
        )

    def test_suppress(self):
        artifact = Artifact(os.path.join(self.base_path, "suppress.go"))
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_lowercase_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_lowercase_rule.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiline(self):
        # TODO: not testing multiline
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiline.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiple_comments(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_comments.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_multiple_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_rules.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_preceding(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_preceding.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(9, result.location.start_line)
        self.assertEqual(9, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_spaced_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_spaced_rules.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.NOTE, result.level)
        self.assertEqual(-1.0, result.rank)

    def test_suppress_wrong_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_wrong_rule.go")
        )
        results = self.parser.parse(artifact)
        self.assertEqual(1, len(results))
        result = results[0]
        self.assertEqual("GO002", result.rule_id)
        self.assertEqual(8, result.location.start_line)
        self.assertEqual(8, result.location.end_line)
        self.assertEqual(9, result.location.start_column)
        self.assertEqual(16, result.location.end_column)
        self.assertEqual(Level.ERROR, result.level)
        self.assertEqual(-1.0, result.rank)
