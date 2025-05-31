# Copyright 2024 Secure Sauce LLC
from abc import ABC
from abc import abstractmethod

from precli.core.artifact import Artifact


class Target(ABC):
    def __init__(self):
        self.FILE_EXTS = (
            ".cpp",
            ".cc",
            ".cxx",
            ".hpp",
            ".h",
            ".cs",
            ".css",
            ".hs",
            ".lhs",
            ".js",
            ".go",
            ".java",
            ".pl",
            ".pm",
            ".t",
            ".php",
            ".phtml",
            ".php3",
            ".php4",
            ".php5",
            ".py",
            ".pyw",
            ".rb",
            ".scala",
            ".swift",
            ".ts",
            ".tsx",
        )

    @abstractmethod
    def discover(self, target: str, recursive: bool) -> list[Artifact]:
        pass
