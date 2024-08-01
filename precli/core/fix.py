# Copyright 2023 Secure Sauce LLC
from typing import Optional

from precli.core.location import Location


class Fix:
    def __init__(
        self,
        description: str,
        deleted_location: Location,
        inserted_content: Optional[str] = None,
    ):
        self._description = description
        self._deleted_location = deleted_location
        self._inserted_content = inserted_content

    @property
    def description(self) -> str:
        """Describes the proposed fix."""
        return self._description

    @property
    def deleted_location(self) -> Location:
        """Specifies the location to delete."""
        return self._deleted_location

    @property
    def inserted_content(self) -> Optional[str]:
        """Content to insert at location specified by deleted_location."""
        return self._inserted_content
