# Copyright 2023 Secure Saurce LLC
from tree_sitter import Node

from precli.core.argument import Argument


class Call:
    def __init__(
        self,
        node: Node,
        name: str,
        name_qual: str,
        args: list = None,
        kwargs: dict = None,
    ):
        self._node = node
        self._name = name
        self._name_qual = name_qual
        self._args = args if args is not None else []
        self._kwargs = kwargs if kwargs is not None else {}

        if self._node.children:
            # Assign nodes to the call attribute/identifier and argument
            # list
            self._func_node = node.children[0]
            self._arg_list_node = node.children[1]
            self._var_node = Call._get_var_node(self._func_node)
            self._ident_node = Call._get_func_ident(self._func_node)

    @staticmethod
    def _get_var_node(node: Node) -> Node:
        if (
            len(node.named_children) >= 2
            and node.named_children[0].type in ("identifier", "attribute")
            and node.named_children[1].type == "identifier"
        ):
            return node.named_children[0]
        elif node.type == "attribute":
            return Call._get_var_node(node.named_children[0])

    @staticmethod
    def _get_func_ident(node: Node) -> Node:
        # TODO(ericwb): does this function fail with nested calls?
        if node.type == "attribute":
            return Call._get_func_ident(node.named_children[1])
        if node.type == "identifier":
            return node

    @property
    def node(self) -> Node:
        """
        The node representing this call.

        :return: node for the call
        :rtype: Node
        """
        return self._node

    @property
    def var_node(self) -> Node:
        """
        The node representing the variable part of a function call.

        For example, if the function call is:
            a.b.c()
        The function node would be a.b

        :return: function for the call
        :rtype: Node
        """
        return self._var_node

    @property
    def function_node(self) -> Node:
        """
        The node representing the entire function of the call.

        For example, if the function call is:
            a.b.c()
        The function node would be a.b.c

        :return: function for the call
        :rtype: Node
        """
        return self._func_node

    @property
    def identifier_node(self) -> Node:
        """
        The node representing just the identifier of the function.

        For example, if the function call is:
            a.b.c()
        The identifier node would be c

        :return: identifier of the function
        :rtype: Node
        """
        return self._ident_node

    @property
    def name(self) -> str:
        """
        The name of the function call.

        :return: name of function
        :rtype: str
        """
        return self._name

    @property
    def name_qualified(self) -> str:
        """
        The fully qualified name of the function.

        :return: fully qualified name of function
        :rtype: str
        """
        return self._name_qual

    def get_argument(
        self, position: int = -1, name: str = None, default: Argument = None
    ) -> Argument:
        if position >= 0:
            for i, child in enumerate(self._arg_list_node.named_children):
                if child.type == "keyword_argument":
                    break
                if i == position:
                    return Argument(
                        node=child,
                        value=self._args[position],
                        position=position,
                    )
        if name is not None:
            for child in self._arg_list_node.named_children:
                if child.type == "keyword_argument":
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
