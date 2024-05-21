# Copyright 2024 Secure Sauce LLC
from tree_sitter import Node

from precli.core.argument import Argument
from precli.parsers import tokens


class Call:
    def __init__(
        self,
        node: Node,
        name: str,
        name_qual: str,
        func_node: Node = None,
        var_node: Node = None,
        ident_node: Node = None,
        arg_list_node: Node = None,
        args: list = None,
        kwargs: dict = None,
    ):
        self._node = node
        self._name = name
        self._name_qual = name_qual
        self._func_node = func_node
        self._var_node = var_node
        self._ident_node = ident_node
        self._arg_list_node = arg_list_node
        self._args = args if args is not None else []
        self._kwargs = kwargs if kwargs is not None else {}

    @property
    def node(self) -> Node:
        """The node representing this call."""
        return self._node

    @property
    def var_node(self) -> Node:
        """
        The node representing the variable part of a function call.

        For example, if the function call is:
            a.b.c()
        The function node would be a.b
        """
        return self._var_node

    @property
    def function_node(self) -> Node:
        """
        The node representing the entire function of the call.

        For example, if the function call is:
            a.b.c()
        The function node would be a.b.c
        """
        return self._func_node

    @property
    def identifier_node(self) -> Node:
        """
        The node representing just the identifier of the function.

        For example, if the function call is:
            a.b.c()
        The identifier node would be c
        """
        return self._ident_node

    @property
    def name(self) -> str:
        """The name of the function call."""
        return self._name

    @property
    def name_qualified(self) -> str:
        """The fully qualified name of the function."""
        return self._name_qual

    @property
    def arg_list_node(self) -> Node:
        return self._arg_list_node

    def get_argument(
        self, position: int = -1, name: str = None, default: Argument = None
    ) -> Argument:
        if position >= 0:
            for i, child in enumerate(self._arg_list_node.named_children):
                if child.type == tokens.KEYWORD_ARGUMENT:
                    break
                if i == position:
                    return Argument(
                        node=child,
                        value=self._args[position],
                        position=position,
                    )
        if name is not None:
            for child in self._arg_list_node.named_children:
                if child.type == tokens.KEYWORD_ARGUMENT:
                    keyword = child.named_children[0].text.decode()
                    if keyword == name:
                        return Argument(
                            node=child.named_children[1],
                            value=self._kwargs.get(name),
                            name=name,
                        )
        return default if default else Argument(node=None, value=None)

    def __repr__(self) -> str:
        return self._node.text.decode()
