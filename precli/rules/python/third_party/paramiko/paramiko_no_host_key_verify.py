# Copyright 2023 Secure Saurce LLC
from precli.core.config import Config
from precli.core.level import Level
from precli.core.location import Location
from precli.core.result import Result
from precli.rules import Rule


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
                ],
                "paramiko.*": [
                    "SSHClient",
                    "AutoAddPolicy",
                    "WarningPolicy",
                ],
            },
            config=Config(enabled=False),
        )

    def analyze(self, context: dict, **kwargs: dict) -> Result:
        call = kwargs.get("call")

        if call.name_qualified in [
            "paramiko.SSHClient.set_missing_host_key_policy",
            "paramiko.client.SSHClient.set_missing_host_key_policy",
        ]:
            argument = call.get_argument(position=0, name="policy")
            policy = argument.value

            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(node=argument.identifier_node),
                description="Use 'RejectPolicy' as the 'policy' argument"
                " to safely reject unknown host keys.",
                inserted_content="RejectPolicy",
            )

            if policy in [
                "paramiko.AutoAddPolicy",
                "paramiko.client.AutoAddPolicy",
            ]:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.ERROR,
                    message=self.message.format("AutoAddPolicy"),
                    fixes=fixes,
                )
            if policy in [
                "paramiko.WarningPolicy",
                "paramiko.client.WarningPolicy",
            ]:
                return Result(
                    rule_id=self.id,
                    location=Location(
                        file_name=context["file_name"],
                        node=argument.identifier_node,
                    ),
                    level=Level.WARNING,
                    message=self.message.format("WarningPolicy"),
                    fixes=fixes,
                )
