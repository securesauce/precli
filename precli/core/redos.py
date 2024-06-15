# Copyright 2024 Secure Sauce LLC
# Copyright 2019 Duo Security
import collections
import itertools
import sys
from re import _constants as constants
from re import _parser as parser


CR = collections.namedtuple("CR", ["cr_min", "cr_max"])

CATEGORY_TO_RANGE = {
    constants.CATEGORY_DIGIT: [(48, 57)],
    constants.CATEGORY_NOT_DIGIT: [(0, 47), (58, sys.maxunicode)],
    constants.CATEGORY_SPACE: [(9, 13), (32, 32)],
    constants.CATEGORY_NOT_SPACE: [(0, 8), (14, 31), (33, sys.maxunicode)],
    constants.CATEGORY_WORD: [(48, 57), (65, 90), (95, 95), (97, 122)],
    constants.CATEGORY_NOT_WORD: [
        (0, 47),
        (58, 64),
        (91, 94),
        (96, 96),
        (123, sys.maxunicode),
    ],
}


class OpNode:
    def __init__(
        self, op: constants._NamedIntConstant, args: tuple, backtrackable=False
    ):
        self.op = op
        self.args = args
        self.backtrackable = backtrackable
        self.children = collections.deque()

    def __str__(self, level: int = 0) -> str:
        result = (
            f"{'  ' * level}{self.op}: args={self.args} "
            f"backtrackable={self.backtrackable}\n"
        )

        for child in self.children:
            result += child.__str__(level + 1)

        return result

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} - op={self.op} args={self.args} "
            f"backtrackable={self.backtrackable}>"
        )


def _build_op_tree_helper(
    node: OpNode, subpattern: parser.SubPattern, parent_backtrackable: bool
):
    prev_sibling_backtrackable = False

    # Iterating in reverse helps with determining backtrackability. A
    # subpattern's ability to backtrack depends on subsequent subpatterns, so
    # it's easier to determine the last subpattern's backtrackability then
    # propagate that information backwards.
    for op, av in reversed(subpattern.data):
        args = []
        subpatterns = []

        if op is constants.BRANCH:
            for a in av[1]:
                subpatterns.append(a)
        elif op is constants.GROUPREF_EXISTS:
            _, item_yes, item_no = av
            subpatterns.append(item_yes)
            if item_no:
                subpatterns.append(item_no)
        elif isinstance(av, (tuple, list)):
            for a in av:
                if isinstance(a, parser.SubPattern):
                    subpatterns.append(a)
                else:
                    args.append(a)
        else:
            args.append(av)

        current_backtrackable = (
            parent_backtrackable or prev_sibling_backtrackable
        )
        new_node = OpNode(op, tuple(args), current_backtrackable)
        for sp in reversed(subpatterns):
            _build_op_tree_helper(new_node, sp, current_backtrackable)

        prev_sibling_backtrackable = (
            prev_sibling_backtrackable or not optional_repeat(new_node)
        )
        node.children.appendleft(new_node)


def build_op_tree(node: OpNode, subpattern: parser.SubPattern):
    _build_op_tree_helper(node, subpattern, False)


class CharacterRange:
    def __init__(self, character_ranges: CR, negate: bool = False):
        self.character_ranges = character_ranges
        self.negate = negate

    @classmethod
    def from_any(cls, _any: tuple):
        """E.g. '.'"""
        return cls([CR(cr_min=0, cr_max=sys.maxunicode)])

    @classmethod
    def from_literal(cls, literal: tuple):
        """E.g. 'a'"""
        return cls([CR(cr_min=literal[0], cr_max=literal[0])])

    @classmethod
    def from_not_literal(cls, not_literal: tuple):
        """E.g. '[^a]'"""
        return cls(
            [CR(cr_min=not_literal[0], cr_max=not_literal[0])], negate=True
        )

    @staticmethod
    def _parse_in_nodes(nodes: tuple):
        results = []
        for node_type, args in nodes:
            match node_type:
                case constants.LITERAL:
                    results.append(CR(cr_min=args, cr_max=args))
                case constants.RANGE:
                    results.append(CR(cr_min=args[0], cr_max=args[1]))
                case constants.CATEGORY:
                    for c, r in CATEGORY_TO_RANGE.items():
                        if args is c:
                            results.extend(
                                CR(cr_min=r_min, cr_max=r_max)
                                for r_min, r_max in r
                            )

        return results

    @classmethod
    def from_in(cls, _in: tuple):
        """E.g. '[abcA-Z]'"""
        character_ranges = cls._parse_in_nodes(_in)
        return cls(character_ranges)

    @classmethod
    def from_not_in(cls, not_in: tuple):
        """E.g. '[^abcA-Z]'"""
        # Avoid initial NEGATE
        character_ranges = cls._parse_in_nodes(not_in[1:])
        return cls(character_ranges, negate=True)

    @classmethod
    def from_op_node(cls, node: OpNode):
        match node.op:
            case constants.ANY:
                return cls.from_any(node.args)
            case constants.LITERAL:
                return cls.from_literal(node.args)
            case constants.NOT_LITERAL:
                return cls.from_not_literal(node.args)
            case constants.IN:
                if node.args and node.args[0] == (constants.NEGATE, None):
                    return cls.from_not_in(node.args)
                else:
                    return cls.from_in(node.args)

        # Unsupported OpNode
        return None

    def overlap(self, other_character_range: CR):
        if self.negate and other_character_range.negate:
            # Unless the sets are disjoint and cover the entire character
            # space they will have overlap - let's punt on the logic and
            # assume this is true
            return True
        elif self.negate:
            character_set = {
                i
                for cr in self.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            other_character_set = {
                i
                for cr in other_character_range.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            return bool(other_character_set - character_set)
        elif other_character_range.negate:
            character_set = {
                i
                for cr in self.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            other_character_set = {
                i
                for cr in other_character_range.character_ranges
                for i in range(cr.cr_min, cr.cr_max + 1)
            }
            return bool(character_set - other_character_set)

        return any(
            cr1.cr_min <= cr2.cr_min <= cr1.cr_max
            or cr1.cr_min <= cr2.cr_max <= cr1.cr_max
            for cr1, cr2 in itertools.product(
                self.character_ranges, other_character_range.character_ranges
            )
        )

    def __repr__(self) -> str:
        ranges = ", ".join(
            str((cr.cr_min, cr.cr_max)) for cr in self.character_ranges
        )
        return (
            f"<{self.__class__.__name__} - negate={self.negate} "
            f"ranges={ranges}>"
        )


def optional_repeat(node: OpNode):
    if node.op not in parser._REPEATCODES:
        return False

    repeat_min, _ = node.args

    return repeat_min == 0


def large_repeat(node: OpNode):
    if node.op not in parser._REPEATCODES:
        return False

    _, repeat_max = node.args

    # Repetition sizes that cause catastrophic backtracking depend on many
    # factors including subject length, machine hardware, and the repetition
    # size itself. This value was mostly arbitrarily chosen after running a
    # few basic catastrophic cases. We may consider making it configurable
    # in the future.
    large_max = 10

    return (
        # e.g. '{min,}', '+', '*'
        repeat_max is constants.MAXREPEAT
        or repeat_max >= large_max
    )


def max_nested_quantifiers(node: OpNode):
    if not node.children:
        return 0

    child_max = max(max_nested_quantifiers(child) for child in node.children)
    is_catastrophic = int(large_repeat(node) and node.backtrackable)

    return is_catastrophic + child_max


def inclusive_alternation_branch(branch_node: OpNode):
    character_ranges = (
        CharacterRange.from_op_node(node) for node in branch_node.children
    )
    return any(
        cr1.overlap(cr2)
        for cr1, cr2 in itertools.combinations(
            filter(None, character_ranges), 2
        )
    )


def _mutually_inclusive_alternation_helper(
    node: OpNode, nested_quantifier: bool
):
    if not node.children:
        return False

    nested_quantifier = nested_quantifier or large_repeat(node)

    inclusive_alternation = False
    if node.op is constants.BRANCH:
        inclusive_alternation = inclusive_alternation_branch(node)

    return any(
        (nested_quantifier and inclusive_alternation and node.backtrackable)
        or _mutually_inclusive_alternation_helper(child, nested_quantifier)
        for child in node.children
    )


def mutually_inclusive_alternation(node: OpNode):
    return _mutually_inclusive_alternation_helper(node, False)


def catastrophic(pattern: str) -> bool:
    try:
        subpattern = parser.parse(pattern)
    except constants.error:
        return False

    root = OpNode(None, ())

    build_op_tree(root, subpattern)
    nested_quantifiers = max_nested_quantifiers(root) > 1
    alternation = mutually_inclusive_alternation(root)

    return any([nested_quantifiers, alternation])
