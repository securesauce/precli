# Copyright 2023 Secure Saurce LLC
from tree_sitter import Node


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

    @staticmethod
    def _get_func_ident(node: Node) -> Node:
        if node is None:
            return None
        # TODO(ericwb): does this function fail with nested calls?
        if node.type in ["attribute", "selector_expression"]:
            return Argument._get_func_ident(node.named_children[1])
        if node.type in ["identifier", "field_identifier"]:
            return node

    @property
    def node(self) -> Node:
        """
        The node representing this argument.

        :return: node for the argument
        :rtype: Node
        """
        return self._node

    @property
    def identifier_node(self) -> Node:
        """
        The node representing just the identifier of the argument.

        For example, if the function is:
            a.b.c()
        The identifier node would be c

        :return: identifier of the argument
        :rtype: Node
        """
        return self._ident_node

    @property
    def name(self) -> str:
        """
        The name of the keyword argument.

        If this argument is a keyword argument, then name is the
        name component of the name-value pair.

        :return: name of keyword arg
        :rtype: str
        """
        return self._name

    @property
    def position(self) -> int:
        """
        The position of the argument in the arg list.

        If this argument is a positional, then position references
        the index in the arg list of the argument.

        :return: index in arg list
        :rtype: int
        """
        return self._position

    @property
    def value(self):
        """
        The value of the argument

        :return: value of argument
        :rtype: object
        """
        return self._value
