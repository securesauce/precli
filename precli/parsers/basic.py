# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import re

from precli.parsers import Parser


# Language map to [file extensions, rule prefix]
LANG_MAP = {
    "c_sharp": [[".cs"], "CS"],
    "cpp": [[".cpp", ".cc", ".cxx", ".hpp", ".h"], "CPP"],
    "css": [[".css"], "CSS"],
    "haskell": [[".hs", ".lhs"], "HS"],
    "javascript": [[".js"], "JS"],
    "ruby": [[".rb"], "RB"],
    "scala": [[".scala"], "SC"],
    "swift": [[".swift"], "SW"],
    # Incompatible Language version 15. Must be between 13 and 14
    # "bash": [[".sh"], "SH"],
    # "c": [[".c", ".h"], "C",],
    # "rust": [[".rs"], "RS"],
    # module 'tree_sitter_typescript' has no attribute 'language'
    # "php": [[".php", ".phtml", ".php3", ".php4", ".php5"], "PHP"],
    # "typescript": [[".ts", ".tsx"], "TS"],
    # Query returns nothing
    # "objc": [[".m", ".mm", ".h"], "OB"],
    # "perl": [[".pl", ".pm", ".t"], "PL"],
    # "html": [[".html", ".htm"], "HTM"],
}


class Basic(Parser):
    def __init__(self, lang: str, **config):
        super().__init__(lang)
        self.SUPPRESS_COMMENT = re.compile(r"suppress:? (?P<rules>[^#]+)?#?")
        self.SUPPRESSED_RULES = re.compile(
            rf"(?:({LANG_MAP[self.lexer][1]}\d\d\dC|[a-z_]+),?)+"
        )

        if "skip_tests" in config:
            self.skip_tests = config["skip_tests"]

        self.suppressions = {}

    def file_extensions(self) -> list[str]:
        return LANG_MAP[self.lexer][0]

    def rule_prefix(self) -> str:
        return LANG_MAP[self.lexer][1]

    def get_file_encoding(self, file_contents: str) -> str:
        return "utf-8"

    def is_test_code(self) -> bool:
        """
        Determine if analyzing test code.

        This function determines if the current position of the analysis
        is within unit test code. The purpose of which is to potentially
        ignore rules in test code.
        """
        return False
