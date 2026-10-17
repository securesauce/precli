# Copyright 2024 Secure Sauce LLC
import os
import pathlib

from ignorelib import IgnoreFilterManager

from precli.core.artifact import Artifact
from precli.targets import Target


class File(Target):
    def discover(self, target: str, recursive: bool) -> list[Artifact]:
        artifacts = []

        if os.path.isdir(target):
            gitignore_mgr = IgnoreFilterManager.build(
                target,
                global_ignore_file_paths=[
                    os.path.join(".git", "info", "exclude"),
                    os.path.expanduser(
                        os.path.join("~", ".config", "git", "ignore")
                    ),
                ],
                global_patterns=[".git"],
                ignore_file_name=".gitignore",
            )
            preignore_mgr = IgnoreFilterManager.build(
                target,
                global_ignore_file_paths=[],
                global_patterns=[],
                ignore_file_name=".preignore",
            )

            if recursive is True:
                for root, _, files in gitignore_mgr.walk():
                    for file in files:
                        path = os.path.join(root, file)
                        file_path = file if os.path.isabs(path) else path

                        if (
                            not preignore_mgr.is_ignored(file_path)
                            and pathlib.Path(path).suffix in self.FILE_EXTS
                        ):
                            artifacts.append(Artifact(path))
            else:
                files = os.listdir(path=target)
                for file in files:
                    if (
                        not (
                            gitignore_mgr.is_ignored(file)
                            or preignore_mgr.is_ignored(file)
                        )
                        and pathlib.Path(file).suffix in self.FILE_EXTS
                    ):
                        artifacts.append(Artifact(os.path.join(target, file)))
        else:
            if pathlib.Path(target).suffix in self.FILE_EXTS or target == "-":
                artifacts.append(Artifact(target))

        return artifacts
