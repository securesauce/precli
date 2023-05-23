# Copyright 2023 Secure Saurce LLC
from precli.core.location import Location


class Fix:
    def __init__(
        self,
        description: str,
        deleted_location: Location,
        inserted_content: str = None,
    ):
        self._description = description
        self._deleted_location = deleted_location
        self._inserted_content = inserted_content

    @property
    def description(self) -> str:
        """
        Describes the proposed fix.

        :return: fix description
        :rtype: str
        """
        return self._description

    @property
    def deleted_location(self) -> Location:
        """
        Specifies the location to delete.

        :return: location object indicating region to delete
        :rtype: Location
        """
        return self._deleted_location

    @property
    def inserted_content(self) -> str:
        """
        Content to insert at location specified by deleted_location.

        :return: content to insert
        :rtype: str
        """
        return self._inserted_content
