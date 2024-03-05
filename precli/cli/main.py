# Copyright 2024 Secure Saurce LLC
import argparse
import logging
import os
import sys
import tempfile
import zipfile
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests
from ignorelib import IgnoreFilterManager
from outdated import check_outdated

import precli
from precli.core import loader
from precli.core.artifact import Artifact
from precli.core.run import Run
from precli.core.tool import Tool
from precli.renderers.detailed import Detailed
from precli.renderers.json import Json
from precli.renderers.markdown import Markdown
from precli.renderers.plain import Plain


def setup_arg_parser():
    parser = argparse.ArgumentParser(
        description="precli - a static analysis security tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-d",
        "--debug",
        dest="debug",
        action="store_true",
        help="turn on debug mode",
    )
    parser.add_argument(
        "targets",
        metavar="targets",
        type=str,
        nargs="*",
        help="source file(s) or directory(s) to be tested",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        help="find and process files in subdirectories",
    )
    parser.add_argument(
        "--enable",
        dest="enable",
        action="store",
        default=None,
        type=str,
        help="comma-separated list of rule IDs or names to enable",
    )
    parser.add_argument(
        "--disable",
        dest="disable",
        action="store",
        default=None,
        type=str,
        help="comma-separated list of rule IDs or names to disable",
    )
    parser.add_argument(
        "--json",
        dest="json",
        action="store_true",
        help="render the output as formatted JSON",
    )
    parser.add_argument(
        "--plain",
        dest="plain",
        action="store_true",
        help="render the output in plain, tabular text",
    )
    parser.add_argument(
        "--markdown",
        dest="markdown",
        action="store_true",
        help="render the output in markdown format",
    )
    parser.add_argument(
        "--gist",
        dest="gist",
        action="store_true",
        help="output the results to Gist",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        action="store",
        type=argparse.FileType("w", encoding="utf-8"),
        default=sys.stdout,
        help="output the results to a file",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="do not display color in output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        help="quiet mode, display less output",
    )
    python_ver = sys.version.replace("\n", "")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {precli.__version__}\n"
        f"  python version = {python_ver}",
    )
    args = parser.parse_args()

    if not args.targets:
        parser.print_usage()
        sys.exit(2)

    return args


def check_for_update():
    local_version = precli.__version__
    try:
        is_outdated, pypi_version = check_outdated("precli", local_version)
    except (ValueError, requests.exceptions.ConnectionError):
        # Local version is greater than the latest version on PyPI
        is_outdated = False

    if is_outdated is True:
        print(f"A new release is available: {local_version} -> {pypi_version}")
        print("To update, run: pip install --upgrade precli")


def build_ignore_mgr(path: str, ignore_file: str) -> IgnoreFilterManager:
    return IgnoreFilterManager.build(
        path,
        global_ignore_file_paths=[],
        global_patterns=[],
        ignore_file_name=ignore_file,
    )


def get_owner_repo(repo_url: str):
    # Extract owner and repository name from the URL
    path = urlparse(repo_url).path.lstrip("/").split("/")
    return path[0], path[1]


def get_default_branch(owner: str, repo: str):
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(api_url)
    response.raise_for_status()
    return response.json().get("default_branch")


def extract_github_repo(owner: str, repo: str, branch: str):
    base_url = "https://api.github.com/repos"
    api_url = f"{base_url}/{owner}/{repo}/zipball/{branch}"
    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, f"{repo}.zip")

    with requests.get(api_url, stream=True) as r:
        r.raise_for_status()
        with open(zip_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)

    os.remove(zip_path)

    for path in os.listdir(temp_dir):
        if path.startswith(f"{owner}-{repo}-"):
            temp_dir = os.path.join(temp_dir, path)

    return temp_dir


def file_to_url(owner, repo, branch, target, root, file):
    target_len = len(target)
    prefix = root[target_len:].lstrip("/")
    urlpath = f"{owner}/{repo}/blob/{branch}"
    rel_path = "/".join([urlpath, prefix, file])
    return urljoin("https://github.com", rel_path)


def discover_files(targets: list[str], recursive: bool):
    artifacts = []

    for target in targets:
        if target.startswith("https://github.com"):
            owner, repo = get_owner_repo(target)
            if repo:
                try:
                    branch = get_default_branch(owner, repo)
                    target = extract_github_repo(owner, repo, branch)
                except requests.exceptions.ConnectionError:
                    owner = None
                    repo = None
        else:
            owner = None
            repo = None

        if os.path.isdir(target):
            gitignore_mgr = build_ignore_mgr(target, ".gitignore")
            preignore_mgr = build_ignore_mgr(target, ".preignore")

            if recursive is True:
                for root, _, files in gitignore_mgr.walk():
                    for file in files:
                        if not preignore_mgr.is_ignored(file):
                            path = os.path.join(root, file)
                            artifact = Artifact(path)
                            if repo:
                                artifact.uri = file_to_url(
                                    owner, repo, branch, target, root, file
                                )
                            artifacts.append(artifact)
            else:
                files = os.listdir(path=target)
                for file in files:
                    if not (
                        gitignore_mgr.is_ignored(file)
                        or preignore_mgr.is_ignored(file)
                    ):
                        artifact = Artifact(os.path.join(target, file))
                        artifacts.append(artifact)
        else:
            artifact = Artifact(target)
            artifacts.append(artifact)

    return artifacts


def create_gist(file, renderer: str):
    match renderer:
        case "json":
            filename = "results.json"
        case "plain":
            filename = "results.txt"
        case "markdown":
            filename = "results.md"
        case "detailed":
            filename = "results.txt"

    with open(file.name) as f:
        file_content = f.read()

    url = "https://api.github.com/gists"
    headers = {
        "Authorization": f"token {os.getenv('GITHUB_TOKEN')}",
        "Accept": "application/vnd.github.v3+json",
    }
    data = {
        "description": "Results of security analysis by Precaution",
        "public": False,
        "files": {filename: {"content": file_content}},
    }
    response = requests.post(url, json=data, headers=headers)

    if response.status_code == 201:
        print(f"Gist created successfully: {response.json()['html_url']}")
    else:
        print(f"Failed to create gist: {response.status_code}")

    file.close()


def main():
    debug = (
        logging.DEBUG
        if "-d" in sys.argv
        or "--debug" in sys.argv
        or os.getenv("DEBUG") is not None
        else logging.INFO
    )
    logging.getLogger("urllib3").setLevel(debug)

    # Setup the command line arguments
    args = setup_arg_parser()

    # Check if a newer version is available
    if args.quiet is False:
        check_for_update()

    enabled = args.enable.split(",") if args.enable else []
    disabled = args.disable.split(",") if args.disable else []
    parsers = loader.load_parsers(enabled, disabled)

    # Compile a list of the targets
    artifacts = discover_files(args.targets, args.recursive)

    # Flatten into a list all rules for all parsers
    rules = [r for parser in parsers.values() for r in parser.rules.values()]

    # Initialize the run
    tool = Tool(
        name="Precaution",
        download_uri=precli.__download_url__,
        full_description=precli.__summary__,
        information_uri=precli.__url__,
        organization=precli.__author__,
        short_description=precli.__summary__,
        version=precli.__version__,
        rules=rules,
    )
    run = Run(tool, parsers, artifacts, debug)

    # Invoke the run
    run.invoke()

    file = args.output
    if args.gist is True:
        file = tempfile.NamedTemporaryFile(mode="w+t")

    if args.json is True:
        renderer = "json"
        json = Json(file=file, no_color=args.no_color)
        json.render(run)
    elif args.plain is True:
        renderer = "plain"
        plain = Plain(file=file, no_color=args.no_color)
        plain.render(run)
    elif args.markdown is True:
        renderer = "markdown"
        markdown = Markdown(file=file, no_color=args.no_color)
        markdown.render(run)
    else:
        renderer = "detailed"
        detailed = Detailed(file=file, no_color=args.no_color)
        detailed.render(run)

    if file.name != sys.stdout.name:
        print(f"Output written to file: {file.name}")

    if args.gist is True:
        create_gist(file, renderer)


if __name__ == "__main__":
    main()
