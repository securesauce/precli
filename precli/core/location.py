# Copyright 2023 Secure Saurce LLC


class Location:
    def __init__(
        self,
        file_name: str,
        start_line: int,
        end_line: int = -1,
        start_column: int = 1,
        end_column: int = -1,
    ):
        self._file_name = file_name
        self._start_line = start_line
        self._end_line = end_line if end_line > 0 else start_line
        self._start_column = start_column
        # TODO: default to end of line
        self._end_column = end_column

    @property
    def file_name(self) -> str:
        return self._file_name

    @property
    def start_line(self) -> int:
        return self._start_line

    @property
    def end_line(self) -> int:
        return self._end_line

    @property
    def start_column(self) -> int:
        return self._start_column

    @property
    def end_column(self) -> int:
        return self._end_column
