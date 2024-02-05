# Copyright 2024 Secure Saurce LLC
from precli.rules import Rule


class Tool:
    def __init__(self, name: str, organization: str, version: str):
        self._name = name
        self._organization = organization
        self._version = version
        self._release_date = ""
        self._download_uri = ""
        self._extensions = []
        self._rules = []
        self._policies = []

    @property
    def name(self) -> str:
        """
        Name of the tool.

        :return: tool name
        :rtype: str
        """
        return self._name

    @property
    def organization(self) -> str:
        """
        Organization that produced the tool.

        :return: organization name
        :rtype: str
        """
        return self._organization

    @property
    def version(self) -> str:
        """
        Version of the tool.

        :return: tool version
        :rtype: str
        """
        return self._version

    @property
    def release_date(self) -> str:
        """
        Release date of the tool.

        :return: release date
        :rtype: str
        """
        return self._release_date

    @property
    def download_uri(self) -> str:
        """
        URI location to download tool.

        :return: location of download
        :rtype: str
        """
        return self._download_uri

    @property
    def extensions(self) -> list:
        """
        Extensions for the tool in use.

        :return: extension list
        :rtype: list
        """
        return self._extensions

    @property
    def rules(self) -> list[Rule]:
        """
        Set of support rules.

        :return: policy list
        :rtype: list
        """
        return self._rules

    @property
    def policies(self) -> list:
        """
        Set of rule configurations.

        :return: policy list
        :rtype: list
        """
        return self._policies
