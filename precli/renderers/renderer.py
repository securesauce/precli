# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod

from precli.core.metrics import Metrics
from precli.core.result import Result


class Renderer(ABC):
    def __init__(self, no_color: bool = False):
        self._no_color = no_color

    @abstractmethod
    def render(self, results: list[Result], metrics: Metrics):
        pass
