# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import sys
from functools import cache
from importlib.metadata import entry_points


@cache
def load_extension(group: str, name: str = ""):
    if not name:
        extensions = {}

        if sys.version_info >= (3, 10):
            eps = entry_points(group=group)
        else:
            eps = entry_points()[group]
        for entry_point in eps:
            extension = entry_point.load()()
            extensions[entry_point.name] = extension

        return extensions
    else:
        if sys.version_info >= (3, 10):
            (entry_point,) = entry_points(group=group, name=name)
            return entry_point.load()
        else:
            eps = entry_points()[group]
            for entry_point in eps:
                if entry_point.name == name:
                    return entry_point.load()
