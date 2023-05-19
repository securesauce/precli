# Copyright 2023 Secure Saurce LLC
from abc import ABC
from abc import abstractmethod


class Renderer(ABC):
    def __init__(self, color: bool = False):
        self._color = color

    @abstractmethod
    def render(self, results: list):
        pass
