# Copyright 2024 Secure Sauce LLC
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
    ):
        self._name = name
        self._download_uri = download_uri
        self._full_description = full_description
        self._information_uri = information_uri
        self._organization = organization
        self._short_description = short_description
        self._version = version
        self._release_date = ""
        self._extensions = []
        self._policies = []

    @property
    def name(self) -> str:
        """Name of the tool."""
        return self._name

    @property
    def download_uri(self) -> str:
        """URI location to download tool."""
        return self._download_uri

    @property
    def full_description(self) -> str:
        """Full description of the tool."""
        return self._full_description

    @property
    def information_uri(self) -> str:
        """Main page URL of the project"""
        return self._information_uri

    @property
    def organization(self) -> str:
        """Organization that produced the tool."""
        return self._organization

    @property
    def short_description(self) -> str:
        """Short description of the tool."""
        return self._short_description

    @property
    def version(self) -> str:
        """Version of the tool."""
        return self._version

    @property
    def release_date(self) -> str:
        """Release date of the tool."""
        return self._release_date

    @property
    def extensions(self) -> list:
        """Extensions for the tool in use."""
        return self._extensions

    @property
    def policies(self) -> list:
        """Set of rule configurations."""
        return self._policies
