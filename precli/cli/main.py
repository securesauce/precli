# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import argparse
import logging
import os
import pathlib
import sys
import tempfile
from argparse import ArgumentParser
from datetime import datetime
from importlib import metadata
from importlib import util

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import requests
from rich.console import Console
import yaml

import precli
from precli.i18n import _
from precli.core import loader
from precli.core.artifact import Artifact
from precli.core.run import Run
from precli.renderers import Renderer


BUSL_URL = "https://spdx.org/licenses/BUSL-1.1.html"
GITHUB_URL = "https://github.com"
PYPI_URL = "https://pypi.org"


def setup_arg_parser():
    parser = ArgumentParser(
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
        "-c",
        "--config",
        dest="config",
        action="store",
        type=argparse.FileType("rb"),
        help="configuration file",
    )
    parser.add_argument(
        "--custom-rules",
        dest="custom_rules",
        action="store",
        type=str,
        help="path to directory containing custom rules",
    )
    parser.add_argument(
        "targets",
        metavar="targets",
        type=str,
        nargs="*",
        help="source file(s) or directory(s) to be analyzed",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        help="find and process files in subdirectories",
    )
    enable_grp = parser.add_mutually_exclusive_group()
    enable_grp.add_argument(
        "--enable",
        dest="enable",
        action="store",
        default=None,
        type=str,
        help="comma-separated list of rule IDs or names to enable",
    )
    enable_grp.add_argument(
        "--disable",
        dest="disable",
        action="store",
        default=None,
        type=str,
        help="comma-separated list of rule IDs or names to disable",
    )
    render_grp = parser.add_mutually_exclusive_group()
    render_grp.add_argument(
        "--json",
        dest="renderer",
        action="store_const",
        const="json",
        default="detailed",
        help="render the output as formatted JSON",
    )
    render_grp.add_argument(
        "--plain",
        dest="renderer",
        action="store_const",
        const="plain",
        default="detailed",
        help="render the output in plain, tabular text",
    )
    render_grp.add_argument(
        "--markdown",
        dest="renderer",
        action="store_const",
        const="markdown",
        default="detailed",
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
        type=argparse.FileType("x", encoding="utf-8"),
        default=sys.stdout,
        help="output the results to a file",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        default=os.getenv("NO_COLOR"),
        help="do not display color in output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        help="quiet mode, display less output",
    )
    extensions = ""
    for dist in metadata.distributions():
        if dist.name.startswith("precli-"):
            extensions += f"  {dist.name} {dist.version}\n"
    python_ver = sys.version.replace("\n", "")
    parser.add_argument(
        "--version",
        action="version",
        version=f"precli {precli.__version__}\n"
        f"{extensions}"
        f"Copyright {datetime.now():%Y} Secure Sauce LLC\n"
        f"License BUSL-1.1: Business Source License 1.1 <{BUSL_URL}>\n"
        f"  Python {python_ver}",
    )
    args = parser.parse_args()

    if args.config:
        try:
            args.config = tomllib.load(args.config)
        except tomllib.TOMLDecodeError as err:
            parser.error(
                f"argument -c/--config: can't load '{args.config.name}': {err}"
            )

    if args.custom_rules:
        rule_path = pathlib.Path(args.custom_rules)
        if not rule_path.is_dir():
            parser.error(
                f"argument custom-rules: can't open '{args.custom_rules}': "
                f"[Errno 2] No such directory: '{args.custom_rules}'"
            )

        args.custom_rules = []
        for file in rule_path.glob("*.yaml"):
            if not file.is_file():
                continue
            with open(file, encoding="utf-8") as f:
                try:
                    rule_yaml = yaml.safe_load(f)
                except yaml.YAMLError:
                    parser.error(
                        f"argument custom-rules: failed to load '{file}'"
                    )

                required_fields = {
                    "id",
                    "name",
                    "language",
                    "description",
                    "cwe",
                    "message",
                    "query",
                    "location_node",
                }
                missing = required_fields - rule_yaml.keys()
                if missing:
                    parser.error(
                        f"argument custom-rules: '{file}' missing required "
                        f"fields [{', '.join(missing)}]"
                    )

                # Verify a tree-sitter module is available to process the
                # rule's query.
                lang = rule_yaml["language"]
                if not util.find_spec(f"tree_sitter_{lang}"):
                    parser.error(
                        f"argument custom-rules: tree_sitter_{lang} module "
                        f"unavailable for custom rule '{file}'"
                    )

                args.custom_rules.append(rule_yaml)

    if not args.targets:
        parser.print_usage()
        sys.exit(2)

    for target in args.targets:
        if (
            target != "-"
            and not target.startswith("https://")
            and not pathlib.Path(target).exists()
        ):
            parser.error(
                f"argument targets: can't open '{target}': [Errno 2] No such "
                f"file or directory: '{target}'"
            )

    if args.gist and not os.getenv("GITHUB_TOKEN"):
        parser.error(
            "argument --gist: environment variable GITHUB_TOKEN undefined"
        )

    return args


def find_config(targets: list[str]) -> dict:
    default_confs = (".precli.toml", "precli.toml", "pyproject.toml")

    for target in filter(os.path.isdir, targets):
        for conf in default_confs:
            path = pathlib.Path(target) / conf
            try:
                if path.exists():
                    with open(path, "rb") as f:
                        return tomllib.load(f)
            except tomllib.TOMLDecodeError:
                # TODO: Log but don't exit
                pass

    return {}


def discover_files(targets: list[str], recursive: bool) -> list[Artifact]:
    artifacts = []

    for target in targets:
        if target.startswith(GITHUB_URL):
            ext_name = "github"
        elif target.startswith(PYPI_URL):
            ext_name = "pypi"
        else:
            ext_name = "file"
        target_ext = loader.load_extension(
            group="precli.targets", name=ext_name
        )
        targeter = target_ext()
        artifacts.extend(targeter.discover(target, recursive))

    return artifacts


def create_gist(file, renderer: Renderer):
    filename = f"results.{renderer.file_extension()}"

    with open(file.name, encoding="utf-8") as f:
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
    response = requests.post(url, json=data, headers=headers, timeout=5)

    if response.ok:
        print(_(f"Gist created successfully: {response.json()['html_url']}"))
    else:
        print(_(f"Failed to create gist: {response.status_code}"))

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

    # Attempt to find config files if one not provided
    if not args.config:
        config = find_config(args.targets)
    else:
        config = args.config

    # CLI enabled/disabled override any config in files
    config["enabled"] = (
        args.enable.split(",") if args.enable else config.get("enabled")
    )
    config["disabled"] = (
        args.disable.split(",") if args.disable else config.get("disabled")
    )

    # Compile a list of the targets
    artifacts = discover_files(args.targets, args.recursive)

    if args.gist is True:
        file = tempfile.NamedTemporaryFile(mode="w+t")
    else:
        file = args.output if args.output else sys.stdout

    console = Console(
        file=file,
        no_color=args.no_color or file.name != sys.stdout.name,
        highlight=False,
    )

    # Invoke the run
    run = Run(config, artifacts, debug, args.custom_rules)
    run.invoke()

    # Render the results
    render_ext = loader.load_extension(
        group="precli.renderers", name=args.renderer
    )
    renderer = render_ext(console, args.quiet)
    renderer.render(run)

    if file.name != sys.stdout.name:
        console.print(_(f"Output written to file: {file.name}"))

    if args.gist is True:
        create_gist(file, renderer)

    if run.results:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
