# Copyright 2024 Secure Sauce LLC


def is_str(value) -> bool:
    """True if the value is a tree-sitter node string."""
    if isinstance(value, str) and (
        value.startswith('b"""')
        or value.startswith("b'''")
        or value.startswith('b"')
        or value.startswith("b'")
        or value.startswith('"""')
        or value.startswith("'''")
        or value.startswith('"')
        or value.startswith("'")
    ):
        return True
    return False


def to_str(value: str) -> str:
    """
    Converts a tree-sitter node string value to a
    true string.
    """
    if isinstance(value, str):
        value_str = value
        bytestr = False
        if value_str and value_str[0] == "b":
            value_str = value_str[1:]
            bytestr = True
        if value_str.startswith('"""') or value_str.startswith("'''"):
            value_str = value_str[3:-3]
        elif value_str.startswith('"') or value_str.startswith("'"):
            value_str = value_str[1:-1]
        if bytestr is True:
            value_str = bytes(value_str, encoding="utf-8")

        return value_str
