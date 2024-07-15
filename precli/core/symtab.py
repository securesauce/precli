# Copyright 2023 Secure Sauce LLC
from typing import Self

from precli.core.call import Call


class SymbolTable:
    def __init__(self, name, parent=None):
        self._name = name
        self._parent = parent
        self._symbols = {}

    def name(self) -> str:
        return self._name

    def parent(self) -> Self | None:
        return self._parent

    def put(self, name: str, type: str, value: str) -> None:
        self._symbols[name] = Symbol(name, type, value)

    def get(self, name: str):
        if name in self._symbols:
            return self._symbols[name]
        else:
            # Check top-most scope (global)
            root_symtab = self
            while root_symtab._parent is not None:
                root_symtab = root_symtab._parent
            return root_symtab._symbols.get(name)

    def remove(self, name: str) -> None:
        if name in self._symbols:
            del self._symbols[name]

    def __contains__(self, name: str) -> bool:
        if name in self._symbols:
            return True
        elif self._parent is not None:
            return name in self._parent
        else:
            return False

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

    def push_call(self, call: Call) -> None:
        self._call_history.append(call)

    @property
    def call_history(self) -> list[Call]:
        return self._call_history

    def __repr__(self) -> str:
        return f"Symbol (type: {self._type}, value: {self._value})"
