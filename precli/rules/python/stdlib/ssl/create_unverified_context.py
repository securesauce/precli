# Copyright 2023 Secure Saurce LLC
from precli.core.location import Location
from precli.core.result import Result
from precli.core.rule import Rule


class CreateUnverifiedContext(Rule):
    def __init__(self, id: str):
        super().__init__(
            id=id,
            name="improper_certificate_validation",
            full_descr=__doc__,
            cwe_id=295,
            message="The '{}' function does not properly validate "
            "certificates.",
            targets=("call"),
        )

    def analyze(self, context: dict, *args: list, **kwargs: dict) -> Result:
        """
        _create_unverified_context(
            protocol=None,
            *,
            cert_reqs=<VerifyMode.CERT_NONE: 0>,
            check_hostname=False,
            purpose=<Purpose.SERVER_AUTH: _ASN1Object(
                nid=129,
                shortname='serverAuth',
                longname='TLS Web Server Authentication',
                oid='1.3.6.1.5.5.7.3.1'
            )>,
            certfile=None,
            keyfile=None,
            cafile=None,
            capath=None,
            cadata=None
        )
        create_default_context(
            purpose=<Purpose.SERVER_AUTH: _ASN1Object(
                nid=129,
                shortname='serverAuth',
                longname='TLS Web Server Authentication',
                oid='1.3.6.1.5.5.7.3.1'
            )>,
            *,
            cafile=None,
            capath=None,
            cadata=None
        )
        """
        if Rule.match_calls(context, ["ssl._create_unverified_context"]):
            fixes = Rule.get_fixes(
                context=context,
                deleted_location=Location(kwargs.get("func_node")),
                description="Use 'create_default_context' to safely validate "
                "certificates.",
                inserted_content="create_default_context",
            )
            return Result(
                rule_id=self.id,
                location=Location(
                    context["file_name"], kwargs.get("func_node")
                ),
                message=self.message.format(context["func_call_qual"]),
                fixes=fixes,
            )
