# Copyright 2024 Secure Sauce LLC
import linecache


class LineCache:
    def __init__(self, file_name: str, file_contents: str):
        """
        Initialize the cache with the given file contents.

        :param file_name: Name of the file (can be <stdin>.
        :param file_contents: A string containing the entire file data.
        """
        self._file_name = file_name
        if self._file_name == "<stdin>":
            self._lines = file_contents.splitlines(keepends=True)

    def getline(self, lineno: int) -> str:
        """
        Return the line from the file contents at the given line number.

        :param lineno: The line number to fetch, 1-based.
        :return: The line at the specified line number, or an empty string if
                 the line does not exist.
        """
        if self._file_name != "<stdin>":
            return linecache.getline(self._file_name, lineno)
        else:
            if 0 < lineno <= len(self._lines):
                return self._lines[lineno - 1]
            return ""
