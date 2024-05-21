# Copyright 2024 Secure Sauce LLC
import os

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.parsers import go


class TestGo:
    @classmethod
    def setup_class(cls):
        cls.parser = go.Go()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "parsers",
            "examples",
        )

    def test_suppress(self):
        artifact = Artifact(os.path.join(self.base_path, "suppress.go"))
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_lowercase_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_lowercase_rule.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.ERROR
        assert result.rank == -1.0

    def test_suppress_multiline(self):
        # TODO: not testing multiline
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiline.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_multiple_comments(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_comments.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_multiple_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_rules.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_preceding(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_preceding.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 9
        assert result.location.end_line == 9
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_spaced_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_spaced_rules.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_wrong_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_wrong_rule.go")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "GO002"
        assert result.location.start_line == 8
        assert result.location.end_line == 8
        assert result.location.start_column == 9
        assert result.location.end_column == 16
        assert result.level == Level.ERROR
        assert result.rank == -1.0
