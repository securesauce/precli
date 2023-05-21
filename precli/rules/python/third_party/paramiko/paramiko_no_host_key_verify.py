# Copyright 2023 Secure Saurce LLC
from precli.core.level import Level
from precli.core.result import Result
from precli.core.rule import Rule


class ParamikoNoHostKeyVerify(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' missing host key policy will not properly "
            "verify the SSH server's host key.",
            targets=("call"),
            wildcards={
                "paramiko.client.*": [
                    "SSHClient",
                    "AutoAddPolicy",
                    "WarningPolicy",
                ]
            },
        )

    def analyze(self, context: dict) -> Result:
        if Rule.match_calls(
            context,
            ["paramiko.client.SSHClient.set_missing_host_key_policy"],
        ):
            if (
                node := Rule.match_call_pos_arg(
                    context, 0, ["paramiko.client.AutoAddPolicy"]
                )
            ) is not None:
                context["node"] = node
                fixes = Rule.get_fixes(
                    context=context,
                    description="Use 'RejectPolicy' as the 'policy' argument"
                    " to safely reject unknown host keys.",
                    inserted_content="RejectPolicy",
                )
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format("AutoAddPolicy"),
                    fixes=fixes,
                )
            if (
                node := Rule.match_call_kwarg(
                    context, "policy", ["paramiko.client.AutoAddPolicy"]
                )
            ) is not None:
                context["node"] = node
                fixes = Rule.get_fixes(
                    context=context,
                    description="Use 'RejectPolicy' as the 'policy' argument"
                    " to safely reject unknown host keys.",
                    inserted_content="RejectPolicy",
                )
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.ERROR,
                    message=self.message.format("AutoAddPolicy"),
                    fixes=fixes,
                )
            if (
                node := Rule.match_call_pos_arg(
                    context, 0, ["paramiko.client.WarningPolicy"]
                )
            ) is not None:
                context["node"] = node
                fixes = Rule.get_fixes(
                    context=context,
                    description="Use 'RejectPolicy' as the 'policy' argument"
                    " to safely reject unknown host keys.",
                    inserted_content="RejectPolicy",
                )
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.WARNING,
                    message=self.message.format("WarningPolicy"),
                    fixes=fixes,
                )
            if (
                node := Rule.match_call_kwarg(
                    context, "policy", ["paramiko.client.WarningPolicy"]
                )
            ) is not None:
                context["node"] = node
                fixes = Rule.get_fixes(
                    context=context,
                    description="Use 'RejectPolicy' as the 'policy' argument"
                    " to safely reject unknown host keys.",
                    inserted_content="RejectPolicy",
                )
                return Result(
                    rule_id=self.id,
                    context=context,
                    level=Level.WARNING,
                    message=self.message.format("WarningPolicy"),
                    fixes=fixes,
                )
