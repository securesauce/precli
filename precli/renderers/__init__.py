# Copyright 2024 Secure Saurce LLC
import sys
from abc import ABC
from abc import abstractmethod

from rich import console

from precli.core.run import Run


class Renderer(ABC):
    def __init__(self, file: sys.stdout, no_color: bool = False):
        self._file = file
        self._no_color = True if file.name != sys.stdout.name else no_color
        self.console = console.Console(
            file=file,
            no_color=no_color,
            highlight=False,
        )

    @abstractmethod
    def render(self, run: Run):
        pass
