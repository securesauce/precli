# Copyright 2024 Secure Saurce LLC
from precli.core.artifact import Artifact
from precli.core.fix import Fix
from precli.core.kind import Kind
from precli.core.level import Level
from precli.core.linecache import LineCache
from precli.core.location import Location
from precli.core.suppression import Suppression
from precli.rules import Rule


class Result:
    def __init__(
        self,
        rule_id: str,
        location: Location,
        artifact: Artifact = None,
        kind: Kind = Kind.FAIL,
        level: Level = None,
        message: str = None,
        fixes: list[Fix] = None,
        suppression: Suppression = None,
        snippet: str = None,
    ):
        self._rule_id = rule_id
        self._artifact = artifact
        self._kind = kind
        default_config = Rule.get_by_id(self._rule_id).default_config
        self._rank = default_config.rank
        if level:
            self._level = level
        else:
            self._level = default_config.level
        self._location = location
        if message:
            self._message = message
        else:
            self._message = Rule.get_by_id(self._rule_id).message
        self._fixes = fixes if fixes is not None else []
        self._suppression = suppression
        if snippet is not None:
            self._snippet = snippet
        else:
            self._init_snippet(artifact)

    def _init_snippet(self, artifact: Artifact):
        if artifact is not None:
            linecache = LineCache(
                artifact.file_name,
                artifact.contents.decode(),
            )
            self._snippet = ""
            for i in range(
                self._location.start_line - 1, self._location.end_line + 2
            ):
                self._snippet += linecache.getline(i)

    @property
    def rule_id(self) -> str:
        """
        The ID of the rule.

        The IDs match ??XXX where ?? is language identifier and XXX is a
        unique number.

        :return: rule ID
        :rtype: str
        """
        return self._rule_id

    @property
    def artifact(self) -> Artifact:
        """
        Artifact, typically the file.

        :return: the artifact
        :rtype: Artifact
        """
        return self._artifact

    @artifact.setter
    def artifact(self, artifact):
        """
        Set the file artifact.

        :param Artifact artifact: file artifact
        """
        self._artifact = artifact
        self._init_snippet(artifact)

    @property
    def location(self) -> Location:
        """
        The location of the issue.

        A location object indicates coordinates within a source file where
        the issue was found.

        :return: location
        :rtype: Location
        """
        return self._location

    @property
    def kind(self) -> Kind:
        """
        The nature of the result.

        Typically having a value of pass or fail to indicate the nature of
        the result.

        :return: kind or nature of result
        :rtype: Kind
        """
        return self._kind

    @property
    def level(self) -> Level:
        """
        The result severity level.

        If the result is being supporessed, then the level is set to NOTE.

        :return: severity level
        :rtype: Level
        """
        return self._level if self._suppression is None else Level.NOTE

    @property
    def message(self) -> str:
        """
        The result issue message.

        :return: issue message
        :rtype: str
        """
        if self._suppression is None:
            return self._message
        else:
            return "This issue is being suppressed via an inline comment."

    @property
    def rank(self) -> float:
        """
        The rank of the issue.

        The value defaults to the value from the default configuration of the
        rule.

        :return: rank
        :rtype: float
        """
        return self._rank

    @property
    def fixes(self) -> list[Fix]:
        """
        The suggested fixes for the issue.

        :return: list of fixes
        :rtype: list
        """
        return self._fixes if self._suppression is None else []

    @property
    def suppression(self) -> Suppression:
        """
        Possible suppressions of the result.

        :return: suppression or None
        :rtype: Suppression
        """
        return self._suppression

    @suppression.setter
    def suppression(self, suppression):
        """
        Set the suppression of this result

        :param Suppression suppression: suppression
        """
        self._suppression = suppression

    @property
    def snippet(self) -> str:
        """
        Snippet of context of the code.

        :return: snippet of context
        :rtype: str
        """
        return self._snippet
