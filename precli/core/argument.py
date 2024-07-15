# Copyright 2024 Secure Sauce LLC
from tree_sitter import Node

from precli.core import utils
from precli.parsers import tokens


class Argument:
    def __init__(
        self,
        node: Node,
        value,
        name: str = None,
        position: int = -1,
    ):
        self._node = node
        self._name = name
        self._position = position
        self._value = value
        self._ident_node = Argument._get_func_ident(self._node)
        self._is_str = utils.is_str(value)
        self._value_str = utils.to_str(value) if self._is_str else None

    @staticmethod
    def _get_func_ident(node: Node) -> Node | None:
        if node is None:
            return None
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == tokens.CALL:
            return Argument._get_func_ident(node.named_children[0])
        if node.type in [tokens.ATTRIBUTE, tokens.SELECTOR_EXPRESSION]:
            return Argument._get_func_ident(node.named_children[1])
        if node.type in [tokens.IDENTIFIER, tokens.FIELD_IDENTIFIER]:
            return node

    @property
    def node(self) -> Node:
        """The node representing this argument."""
        return self._node

    @property
    def identifier_node(self) -> Node | None:
        """
        The node representing just the identifier of the argument.

        For example, if the function is:
            a.b.c()
        The identifier node would be c
        """
        return self._ident_node

    @property
    def name(self) -> str:
        """
        The name of the keyword argument.

        If this argument is a keyword argument, then name is the
        name component of the name-value pair.
        """
        return self._name

    @property
    def position(self) -> int:
        """
        The position of the argument in the arg list.

        If this argument is a positional, then position references
        the index in the arg list of the argument.
        """
        return self._position

    @property
    def is_str(self) -> bool:
        """True if the value is a true string."""
        return self._is_str

    @property
    def value(self):
        """The value of the argument."""
        return self._value

    @property
    def value_str(self) -> str | None:
        """The value as a true string."""
        return self._value_str
