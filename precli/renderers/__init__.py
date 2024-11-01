# Copyright 2024 Secure Sauce LLC
from abc import ABC
from abc import abstractmethod

from rich.console import Console

from precli.core.run import Run


class Renderer(ABC):
    def __init__(self, console: Console, quiet: bool):
        self.console = console
        self.quiet = quiet

    @abstractmethod
    def file_extension(self) -> str:
        pass

    @abstractmethod
    def render(self, run: Run):
        pass
