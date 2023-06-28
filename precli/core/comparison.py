# Copyright 2023 Secure Saurce LLC
from tree_sitter import Node


class Comparison:
    def __init__(
        self,
        node: Node,
        left_hand: str,
        operator: str,
        right_hand: str,
    ):
        self._node = node
        self._left_hand = left_hand
        self._operator = operator
        self._right_hand = right_hand
        self._left_node = node.children[0]
        self._operator_node = node.children[1]
        self._right_node = node.children[2]

    @property
    def node(self) -> Node:
        """
        The node representing this comparison.

        :return: node for the comparison
        :rtype: Node
        """
        return self._node

    @property
    def left_node(self) -> Node:
        """
        The left node of the comparison.

        :return: left node of comparison
        :rtype: Node
        """
        return self._left_node

    @property
    def operator_node(self) -> Node:
        """
        The operator node of this comparison.

        :return: operator node of comparison
        :rtype: Node
        """
        return self._operator_node

    @property
    def right_node(self) -> Node:
        """
        The right node of the comparison.

        :return: right node of comparison
        :rtype: Node
        """
        return self._right_node

    @property
    def left_hand(self) -> str:
        """
        The left hand side of the comparison.

        :return: left part of comparison
        :rtype: str
        """
        return self._left_hand

    @property
    def operator(self) -> str:
        """
        The operator of this comparison.

        :return: operator of comparison
        :rtype: str
        """
        return self._operator

    @property
    def right_hand(self) -> str:
        """
        The right hand side of the comparison.

        :return: right part of comparison
        :rtype: str
        """
        return self._right_hand
