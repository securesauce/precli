# Copyright 2024 Secure Saurce LLC


class Artifact:
    def __init__(self, file_name: str, uri: str = None):
        self._file_name = file_name
        # TODO: if uri is None, use file:///
        self._uri = uri
        self._contents = None
        self._language = None

    @property
    def file_name(self) -> str:
        """
        The name of the file.

        :return: file name
        :rtype: str
        """
        return self._file_name

    @file_name.setter
    def file_name(self, file_name):
        """
        Set the file name

        :param str file_name: file name
        """
        self._file_name = file_name

    @property
    def uri(self) -> str:
        """
        The URI of the artifact.

        :return: URI
        :rtype: str
        """
        return self._uri

    @uri.setter
    def uri(self, uri):
        """
        Set the artifact URI.

        :param str uri: URI
        """
        self._uri = uri

    @property
    def contents(self) -> str:
        """
        The contents of the artifact.

        :return: typically file contents
        :rtype: str
        """
        return self._contents

    @contents.setter
    def contents(self, contents) -> str:
        """
        Set the contents (for typically the file).

        :param str contents: file contents
        """
        self._contents = contents

    @property
    def language(self) -> str:
        """
        The programming language for this artifact.

        :return: programming language name
        :rtype: str
        """
        return self._language

    @language.setter
    def language(self, language) -> str:
        """
        Set the programming language.

        :param str language: program language
        """
        self._language = language
