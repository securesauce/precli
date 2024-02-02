# Copyright 2024 Secure Saurce LLC
from importlib.metadata import entry_points


def load_parsers(enabled: list[str], disabled: list[str]) -> dict:
    parsers = {}

    discovered_plugins = entry_points(group="precli.parsers")
    for plugin in discovered_plugins:
        parser = plugin.load()(enabled, disabled)
        parsers[parser.lexer] = parser

    return parsers
