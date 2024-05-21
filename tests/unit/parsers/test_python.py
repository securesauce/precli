# Copyright 2024 Secure Sauce LLC
import os

import pytest

from precli.core.artifact import Artifact
from precli.core.level import Level
from precli.parsers import python


class TestPython:
    @classmethod
    def setup_class(cls):
        cls.parser = python.Python()
        cls.base_path = os.path.join(
            "tests",
            "unit",
            "parsers",
            "examples",
        )

    def test_bad_coding(self):
        artifact = Artifact(os.path.join(self.base_path, "bad_coding.py"))
        self.parser.parse(artifact)

    def test_expression_list_assignment(self):
        artifact = Artifact(
            os.path.join(self.base_path, "expression_list_assignment.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 0

    def test_expression_list_assignment_uneven(self):
        artifact = Artifact(
            os.path.join(
                self.base_path, "expression_list_assignment_uneven.py"
            )
        )
        results = self.parser.parse(artifact)
        assert len(results) == 0

    def test_importlib_import_module(self):
        artifact = Artifact(
            os.path.join(self.base_path, "importlib_import_module.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 0

    def test_pep3120(self):
        artifact = Artifact(os.path.join(self.base_path, "pep3120.py"))
        with pytest.raises(UnicodeDecodeError):
            self.parser.parse(artifact)

    def test_suppress(self):
        artifact = Artifact(os.path.join(self.base_path, "suppress.py"))
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_lowercase_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_lowercase_rule.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.ERROR
        assert result.rank == -1.0

    def test_suppress_multiline(self):
        # TODO: not testing multiline
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiline.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_multiple_comments(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_comments.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_multiple_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_multiple_rules.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_preceding(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_preceding.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 5
        assert result.location.end_line == 5
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_spaced_rules(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_spaced_rules.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.NOTE
        assert result.rank == -1.0

    def test_suppress_wrong_rule(self):
        artifact = Artifact(
            os.path.join(self.base_path, "suppress_wrong_rule.py")
        )
        results = self.parser.parse(artifact)
        assert len(results) == 1
        result = results[0]
        assert result.rule_id == "PY004"
        assert result.location.start_line == 4
        assert result.location.end_line == 4
        assert result.location.start_column == 8
        assert result.location.end_column == 11
        assert result.level == Level.ERROR
        assert result.rank == -1.0
