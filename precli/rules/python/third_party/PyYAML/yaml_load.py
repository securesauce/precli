# Copyright 2023 Secure Saurce LLC
from precli.core.result import Result
from precli.core.rule import Rule


class YamlLoad(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="deserialization_of_untrusted_data",
            full_descr=__doc__,
            cwe_id=502,
            message="Usage of {} can allow instantiation of arbitrary "
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

    def analyze(self, context: dict) -> Result:
        if (call_node := Rule.match_calls(context, ["yaml.load"])) is not None:
            args = context["func_call_args"]
            loader = context["func_call_kwargs"].get("Loader")

            if len(args) > 1:
                if isinstance(args[1], str) and args[1] not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    context["node"] = Rule.get_positional_arg(
                        context["node"], 1
                    )
                    fixes = Rule.get_fixes(
                        context=context,
                        description="Use SafeLoader to safely load YAML files",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        context=context,
                        message=self.message.format(context["func_call_qual"]),
                        fixes=fixes,
                    )
            elif loader is not None:
                if isinstance(loader, str) and loader not in (
                    "yaml.CSafeLoader",
                    "yaml.SafeLoader",
                ):
                    context["node"] = Rule.get_keyword_arg(
                        context["node"], "Loader"
                    )
                    fixes = Rule.get_fixes(
                        context=context,
                        description="Use SafeLoader to safely load YAML files",
                        inserted_content="SafeLoader",
                    )
                    return Result(
                        rule_id=self.id,
                        context=context,
                        message=self.message.format(context["func_call_qual"]),
                        fixes=fixes,
                    )
            else:
                context["node"] = call_node
                fixes = Rule.get_fixes(
                    context=context,
                    description="Use safe_load to safely load YAML files",
                    inserted_content="safe_load",
                )
                return Result(
                    rule_id=self.id,
                    context=context,
                    message=self.message.format(context["func_call_qual"]),
                    fixes=fixes,
                )
