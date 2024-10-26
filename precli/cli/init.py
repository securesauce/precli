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
        default=".precli.toml",
        help="output the config to given file",
    )

    return parser.parse_args()


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

        # Check if the file already exists and prompt for overwrite
        if path.exists():
            overwrite = input(
                f"The file '{args.output}' already exists. Overwrite? (y/N): "
            )
            if overwrite.lower() != "y":
                print("Operation cancelled.")
                return 1

        # Check if the target file is pyproject.toml and prepare the structure
        if path.name == "pyproject.toml":
            if path.exists():
                with open(path, "rb") as f:
                    doc = tomllib.load(f)
                doc.setdefault("tool", {}).setdefault("precli", {}).update(
                    config
                )
            else:
                doc = {"tool": {"precli": config}}
        else:
            doc = config

        # Write the configuration to the specified file
        with open(path, "wb") as f:
            tomli_w.dump(doc, f)

    except OSError:
        print(f"Error writing to file: {args.output}")
        return 1
    else:
        print(f"Default config written to file: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
