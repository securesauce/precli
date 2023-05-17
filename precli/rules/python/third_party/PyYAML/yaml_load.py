# Copyright 2023 Secure Saurce LLC
from precli.core.fix import Fix
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
        if all(
            [
                Rule.match_calls(context, ["yaml.load"]),
                not Rule.match_call_pos_arg(
                    context, 1, ["yaml.CSafeLoader", "yaml.SafeLoader"]
                ),
                not Rule.match_call_kwarg(
                    context, "Loader", ["yaml.CSafeLoader", "yaml.SafeLoader"]
                ),
            ]
        ):
            fixes = []
            # TODO(ericwb): if loader=yaml.Loader, suggest yaml.SafeLoader

            # if yaml imported, then can switch to safe_load
            if context["node"].children[0].type == "attribute":
                load_node = context["node"].children[0].named_children[1]
                fix = Fix(
                    context=context,
                    description="Use safe_load to safely load YAML files",
                    deleted_start_point=(
                        load_node.start_point[0],
                        load_node.start_point[1],
                    ),
                    deleted_end_point=(
                        load_node.end_point[0],
                        load_node.end_point[1],
                    ),
                    inserted_content="safe_load",
                )
                fixes.append(fix)

            # TODO(ericwb): HARD: if load imported, then either add safe_load
            # to imports or suggest SaleLoader

            return Result(
                rule_id=self.id,
                context=context,
                message=self.message.format(context["func_call_qual"]),
                fixes=fixes,
            )
