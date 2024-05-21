# Copyright 2024 Secure Sauce LLC
from tree_sitter import Node


class Location:
    def __init__(
        self,
        node: Node = None,
        start_line: int = 0,
        end_line: int = -1,
        start_column: int = 1,
        end_column: int = -1,
    ):
        if node is not None:
            self._start_line = node.start_point[0] + 1
            self._start_column = node.start_point[1]
            self._end_line = node.end_point[0] + 1
            self._end_column = node.end_point[1]
        else:
            self._start_line = start_line
            self._end_line = end_line if end_line > 0 else start_line
            self._start_column = start_column
            # TODO: default to end of line
            self._end_column = end_column

    @property
    def start_line(self) -> int:
        """The starting line of the issue."""
        return self._start_line

    @property
    def end_line(self) -> int:
        """The ending line of the issue."""
        return self._end_line

    @property
    def start_column(self) -> int:
        """The starting column of the issue."""
        return self._start_column

    @property
    def end_column(self) -> int:
        """The ending column of the issue."""
        return self._end_column
