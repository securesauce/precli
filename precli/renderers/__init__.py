# Copyright 2024 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod

from precli.core.run import Run


class Renderer(ABC):
    def __init__(self, no_color: bool = False):
        self._no_color = no_color

    @abstractmethod
    def render(self, run: Run):
        pass
