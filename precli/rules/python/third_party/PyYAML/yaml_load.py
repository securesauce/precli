# Copyright 2023 Secure Saurce LLC
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


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
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        if Rule.match_calls(context, ["yaml.load"]):
            call_args = kwargs.get("func_call_args")
            call_kwargs = kwargs.get("func_call_kwargs")
            loader = call_kwargs.get("Loader")

            if len(call_args) > 1:
                if isinstance(call_args[1], str) and call_args[1] not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    node = Rule.get_positional_arg(context["node"], 1)
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'SafeLoader' as the 'Loader' argument"
                        " to safely load YAML files.",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        message=self.message.format(kwargs["func_call_qual"]),
                        fixes=fixes,
                    )
            elif loader is not None:
                if isinstance(loader, str) and loader not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    node = Rule.get_keyword_arg(context["node"], "Loader")
                    node = Rule.get_func_ident(node)
                    fixes = Rule.get_fixes(
                        context=context,
                        deleted_location=Location(node=node),
                        description="Use 'SafeLoader' as the 'Loader' argument"
                        " to safely load YAML files.",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        location=Location(context["file_name"], node),
                        message=self.message.format(context["func_call_qual"]),
                        fixes=fixes,
                    )
            else:
                node = Rule.get_func_ident(kwargs.get("func_node"))
                fixes = Rule.get_fixes(
                    context=context,
                    deleted_location=Location(node=node),
                    description="Use 'yaml.safe_load' to safely load YAML "
                    "files.",
                    inserted_content="safe_load",
                )
                return Result(
                    rule_id=self.id,
                    location=Location(context["file_name"], node),
                    message=self.message.format(context["func_call_qual"]),
                    fixes=fixes,
                )
