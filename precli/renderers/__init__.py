# Copyright 2024 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod

from rich import console

from precli.core.run import Run


class Renderer(ABC):
    def __init__(self, no_color: bool = False):
        self._no_color = no_color
        if no_color is True:
            self.console = console.Console(color_system=None, highlight=False)
        else:
            self.console = console.Console(highlight=False)

    @abstractmethod
    def render(self, run: Run) -> str:
        pass
