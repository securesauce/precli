# Copyright 2024 Secure Sauce LLC
import os
import pathlib
import tarfile
import tempfile
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


PYPI_API = "https://pypi.org"


class PyPI(Target):

    def extract_sdist(self, project: str) -> str:
        api_url = f"{PYPI_API}/pypi/{project}/json"
        temp_dir = tempfile.mkdtemp()
        tar_gz_path = os.path.join(temp_dir, f"{project}.tar.gz")

        with requests.get(api_url, timeout=5) as r:
            r.raise_for_status()
            urls = r.json().get("urls")
            for url in urls:
                if url.get("packagetype") == "sdist":
                    download_url = url.get("url")
                    break

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
        )
        with progress:
            with requests.get(download_url, stream=True, timeout=5) as r:
                r.raise_for_status()

                # TODO: ideally set total to file size, but the Content-Length
                # is not reliably sent in the response header.
                task_id = progress.add_task(
                    "Downloading...", total=url.get("size")
                )
                chunk_size = 8192
                with open(tar_gz_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        f.write(chunk)
                        progress.update(task_id, advance=chunk_size)

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
        )
        with progress:
            with tarfile.open(tar_gz_path, "r:gz") as tar:
                name_list = tar.getnames()
                for name in progress.track(
                    name_list, description="Extracting..."
                ):
                    tar.extract(name, temp_dir)

        os.remove(tar_gz_path)

        return temp_dir

    def discover(self, target: str, recursive: bool) -> list[Artifact]:
        artifacts = []

        # Find project from URL
        # For example: https://pypi.org/project/precli/
        path = urlparse(target).path.lstrip("/").split("/")
        project = path[1]

        try:
            target = self.extract_sdist(project)
        except requests.exceptions.ConnectionError:
            pass

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
            if pathlib.Path(target).suffix in self.FILE_EXTS:
                artifacts.append(Artifact(target))

        return artifacts
