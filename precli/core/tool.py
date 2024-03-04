# Copyright 2024 Secure Saurce LLC
from precli.rules import Rule


class Tool:
    def __init__(
        self,
        name: str,
        download_uri: str,
        full_description: str,
        information_uri: str,
        organization: str,
        short_description: str,
        version: str,
        rules: list[Rule],
    ):
        self._name = name
        self._download_uri = download_uri
        self._full_description = full_description
        self._information_uri = information_uri
        self._organization = organization
        self._short_description = short_description
        self._version = version
        self._rules = rules
        self._release_date = ""
        self._extensions = []
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
    def download_uri(self) -> str:
        """
        URI location to download tool.

        :return: location of download
        :rtype: str
        """
        return self._download_uri

    @property
    def full_description(self) -> str:
        """
        Full description of the tool.

        :return: full description
        :rtype: str
        """
        return self._full_description

    @property
    def information_uri(self) -> str:
        """
        Main page URL of the project

        :return: information URI
        :rtype: str
        """
        return self._information_uri

    @property
    def organization(self) -> str:
        """
        Organization that produced the tool.

        :return: organization name
        :rtype: str
        """
        return self._organization

    @property
    def short_description(self) -> str:
        """
        Short description of the tool.

        :return: short description
        :rtype: str
        """
        return self._short_description

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
        Set of supported rules.

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
