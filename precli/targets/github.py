# Copyright 2024 Secure Sauce LLC
import os
import pathlib
import tempfile
import zipfile
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests
from ignorelib import IgnoreFilterManager
from rich.progress import BarColumn
from rich.progress import DownloadColumn
from rich.progress import MofNCompleteColumn
from rich.progress import Progress
from rich.progress import TextColumn

from precli.core.artifact import Artifact
from precli.targets import Target


GITHUB_API = "https://api.github.com"
GITHUB_URL = "https://github.com"


class GitHub(Target):
    def get_owner_repo(self, repo_url: str) -> tuple[str, str]:
        # Extract owner and repository name from the URL
        path = urlparse(repo_url).path.lstrip("/").split("/")
        return path[0], path[1]

    def get_default_branch(self, owner: str, repo: str) -> str:
        api_url = f"{GITHUB_API}/repos/{owner}/{repo}"
        response = requests.get(api_url, timeout=5)
        response.raise_for_status()
        return response.json().get("default_branch")

    def extract_github_repo(self, owner: str, repo: str, branch: str) -> str:
        api_url = f"{GITHUB_API}/repos/{owner}/{repo}/zipball/{branch}"
        temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(temp_dir, f"{repo}.zip")

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
        )
        with progress:
            with requests.get(api_url, stream=True, timeout=5) as r:
                r.raise_for_status()

                # TODO: ideally set total to file size, but the Content-Length
                # is not reliably sent in the response header.
                task_id = progress.add_task("Downloading...", total=None)
                chunk_size = 8192
                with open(zip_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
                        progress.update(task_id, advance=chunk_size)

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
        )
        with progress:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                name_list = zip_ref.namelist()
                for name in progress.track(
                    name_list, description="Extracting..."
                ):
                    zip_ref.extract(name, temp_dir)

        os.remove(zip_path)

        for path in os.listdir(temp_dir):
            if path.startswith(f"{owner}-{repo}-"):
                temp_dir = os.path.join(temp_dir, path)

        return temp_dir

    def file_to_url(
        self,
        owner: str,
        repo: str,
        branch: str,
        target: str,
        root: str,
        file: str,
    ) -> str:
        target_len = len(target)
        prefix = root[target_len:].lstrip("/")
        urlpath = f"{owner}/{repo}/blob/{branch}"
        rel_path = "/".join([urlpath, prefix, file])
        return urljoin(GITHUB_URL, rel_path)

    def discover(self, target: str, recursive: bool) -> list[Artifact]:
        artifacts = []

        owner, repo = self.get_owner_repo(target)
        if repo:
            try:
                branch = self.get_default_branch(owner, repo)
                target = self.extract_github_repo(owner, repo, branch)
            except requests.exceptions.ConnectionError:
                owner = None
                repo = None

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
                            uri = self.file_to_url(
                                owner, repo, branch, target, root, file
                            )
                            artifacts.append(Artifact(path, uri))
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
            if pathlib.Path(target).suffix in self.FILE_EXTS:
                artifacts.append(Artifact(target))

        return artifacts
