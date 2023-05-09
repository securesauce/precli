# Copyright 2023 Secure Saurce LLC
from typing import Self


class SymbolTable:
    def __init__(self, parent=None):
        self._symbols = {}
        self._parent = parent

    def parent(self) -> Self:
        return self._parent

    def put(self, name: str, type: str, value: str):
        self._symbols[name] = Symbol(name, type, value)

    def get(self, name: str):
        if name in self._symbols:
            return self._symbols[name]
        elif self._parent is not None:
            return self._parent.get(name)
        else:
            return None

    def remove(self, name: str):
        if name in self._symbols:
            del self._symbols[name]

    def __str__(self) -> str:
        return str(self._symbols)


class Symbol:
    def __init__(self, name, type, value):
        self._name = name
        self._type = type
        self._value = value

    @property
    def name(self) -> str:
        return self._name

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Symbol (type: {self._type} value: {self._value})"
