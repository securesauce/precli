# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import argparse
import pathlib
import sys
from argparse import Namespace

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib
import tomli_w

from precli.i18n import _
from precli.core import loader


def setup_arg_parser() -> Namespace:
    parser = argparse.ArgumentParser(
        description="precli-init - create default configuration file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        action="store",
        type=str,
        default=".precli.toml",
        help="output the config to given file (default: .precli.toml)",
    )
    args = parser.parse_args()

    # Prevent overwriting output files except appending to pyproject.toml
    path = pathlib.Path(args.output)
    if path.exists():
        if path.name == "pyproject.toml":
            with open(path, "rb") as f:
                doc = tomllib.load(f)
            if "tool" in doc and "precli" in doc.get("tool"):
                parser.error(
                    f"argument -o/--output: can't write '{args.output}': "
                    f"[Errno 17] Configuration already exist: '[tool.precli]'"
                )
        else:
            parser.error(
                f"argument -o/--output: can't write '{args.output}': "
                f"[Errno 17] File exists: '{args.output}'"
            )

    return args


def get_config() -> dict:
    parsers = loader.load_extension(group="precli.parsers")
    rules = [r for p in parsers.values() for r in p.rules.values()]

    config = {"rule": {}}
    enabled = []
    disabled = []

    for rule in rules:
        config["rule"][rule.id] = {
            "level": rule.config.level,
        }
        if rule.config.enabled:
            enabled.append(rule.id)
        else:
            disabled.append(rule.id)
        if rule.config.parameters:
            for parameter, value in rule.config.parameters.items():
                config["rule"][rule.id][parameter] = value

    config["enabled"] = enabled
    config["disabled"] = disabled

    return config


def main():
    # Setup the command line arguments
    args = setup_arg_parser()

    # Fetch the default configuration
    config = get_config()

    # Write to the given file
    try:
        path = pathlib.Path(args.output)

        # Check if the target file is pyproject.toml and prepare the structure
        if path.name == "pyproject.toml":
            doc = {"tool": {"precli": config}}
        else:
            doc = config

        # Write the configuration to the specified file
        with open(path, "ab") as f:
            tomli_w.dump(doc, f)

    except OSError:
        print(_(f"Error writing to file: {args.output}"))
        return 1
    else:
        print(_(f"Default config written to file: {args.output}"))

    return 0


if __name__ == "__main__":
    sys.exit(main())
