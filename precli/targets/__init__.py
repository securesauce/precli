# Copyright 2024 Secure Sauce LLC
from abc import ABC
from abc import abstractmethod

from precli.core.artifact import Artifact


class Target(ABC):
    def __init__(self):
        self.FILE_EXTS = (".go", ".java", ".py", ".pyw")

    @abstractmethod
    def discover(self, target: str, recursive: bool) -> list[Artifact]:
        pass
