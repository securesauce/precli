# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
from functools import cache
from importlib.metadata import entry_points


@cache
def load_extension(group: str, name: str = ""):
    if not name:
        extensions = {}

        for entry_point in entry_points(group=group):
            extension = entry_point.load()()
            extensions[entry_point.name] = extension

        return extensions
    else:
        (entry_point,) = entry_points(group=group, name=name)
        return entry_point.load()
