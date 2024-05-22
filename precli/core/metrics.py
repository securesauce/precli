# Copyright 2024 Secure Sauce LLC


class Metrics:
    def __init__(
        self,
        files: int,
        lines: int,
        errors: int = 0,
        warnings: int = 0,
        notes: int = 0,
    ):
        self._files = files
        self._lines = lines
        self._errors = errors
        self._warnings = warnings
        self._notes = notes

    @property
    def files(self) -> int:
        """Number of files analyzed."""
        return self._files

    @property
    def lines(self) -> int:
        """Total number of lines analyzed."""
        return self._lines

    @property
    def errors(self) -> int:
        """Total number of errors found."""
        return self._errors

    @property
    def warnings(self) -> int:
        """Total number of warnings found."""
        return self._warnings

    @property
    def notes(self) -> int:
        """Total number of notes found."""
        return self._notes
