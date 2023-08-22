# Copyright 2023 Secure Saurce LLC
from typing import Self

from precli.core.call import Call


class SymbolTable:
    def __init__(self, name, parent=None):
        self._name = name
        self._parent = parent
        self._symbols = {}

    def name(self) -> str:
        return self._name

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
        self._call_history = []

    @property
    def name(self) -> str:
        return self._name

    @property
    def type(self) -> str:
        return self._type

    @property
    def value(self) -> str:
        return self._value

    def push_call(self, call: Call):
        self._call_history.append(call)

    @property
    def call_history(self) -> list[Call]:
        return self._call_history

    def __repr__(self) -> str:
        return f"Symbol (type: {self._type}, value: {self._value})"
