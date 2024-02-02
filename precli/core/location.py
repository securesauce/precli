# Copyright 2024 Secure Saurce LLC
from tree_sitter import Node


class Location:
    def __init__(
        self,
        file_name: str = None,
        url: str = None,
        node: Node = None,
        start_line: int = 0,
        end_line: int = -1,
        start_column: int = 1,
        end_column: int = -1,
        snippet: str = None,
    ):
        self._file_name = file_name
        self._url = url
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
        self._snippet = snippet

    @property
    def file_name(self) -> str:
        """
        Name of the file.

        :return: file name
        :rtype: str
        """
        return self._file_name

    @property
    def url(self) -> str:
        """
        If the original target was given as a URL, this
        property will return that address.

        :return: URL
        :rtype: str
        """
        return self._url

    @url.setter
    def url(self, url: str):
        """
        Set the file location as a URL

        :param str url: file network location
        """
        self._url = url

    @property
    def start_line(self) -> int:
        """
        The starting line of the issue.

        :return: starting line
        :rtype: int
        """
        return self._start_line

    @property
    def end_line(self) -> int:
        """
        The ending line of the issue.

        :return: ending line
        :rtype: int
        """
        return self._end_line

    @property
    def start_column(self) -> int:
        """
        The starting column of the issue.

        :return: starting column
        :rtype: int
        """
        return self._start_column

    @property
    def end_column(self) -> int:
        """
        The ending column of the issue.

        :return: ending column
        :rtype: int
        """
        return self._end_column

    @property
    def snippet(self) -> str:
        """
        Snippet of context of the code.

        :return: snippet of context
        :rtype: str
        """
        return self._snippet

    @snippet.setter
    def snippet(self, snippet):
        """
        Set the code context snippet.

        :param str snippet: context snippet
        """
        self._snippet = snippet
