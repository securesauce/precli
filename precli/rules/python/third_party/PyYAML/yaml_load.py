# Copyright 2023 Secure Saurce LLC
from precli.core.base_rule import Rule
from precli.core.config import Configuration
from precli.core.result import Result


class YamlLoad(Rule):

    def __init__(self):
        super().__init__(
            id="PRE1010",
            name="yaml_load",
            short_descr="",
            full_descr="",
            help_url="",
            configuration=Configuration(),
            cwe=20,
            message="",
        )

    def analyze(self, context: dict) -> Result:
        return None
