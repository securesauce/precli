# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


class YamlLoad(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe_id=502,
            message="Usage of '{}' can allow instantiation of arbitrary "
            "objects.",
            targets=("call"),
            wildcards={
                "yaml.*": [
                    "load",
                    "SafeLoader",
                    "CSafeLoader",
                ]
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in ["yaml.load"]:
            argument = call.get_argument(position=1, name="Loader")
            loader = argument.value

            if loader is not None:
                if isinstance(loader, str) and loader not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(
                            node=argument.identifier_node
                        ),
                        description="Use 'SafeLoader' as the 'Loader' argument"
                        " to safely load YAML files.",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(
                            file_name=context["file_name"],
                            node=argument.identifier_node,
                        ),
                        message=self.message.format(call.name_qualified),
                        fixes=fixes,
                    )
            else:
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=call.identifier_node),
                    description="Use 'yaml.safe_load' to safely load YAML "
                    "files.",
                    inserted_content="safe_load",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=call.identifier_node,
                    ),
                    message=self.message.format(call.name_qualified),
                    fixes=fixes,
                )
