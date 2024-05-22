# Copyright 2024 Secure Sauce LLC
from importlib.metadata import entry_points


def load_parsers() -> dict:
    parsers = {}

    discovered_plugins = entry_points(group="precli.parsers")
    for plugin in discovered_plugins:
        parser = plugin.load()()
        parsers[parser.lexer] = parser

    return parsers
