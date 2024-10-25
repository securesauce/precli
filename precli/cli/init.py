# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import argparse
import sys
from argparse import Namespace

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

    args = parser.parse_args()

    return args


def get_config() -> dict:
    parsers = loader.load_extension(group="precli.parsers")
    rules = [r for p in parsers.values() for r in p.rules.values()]

    config = {"rule": {}}

    for rule in rules:
        config["rule"][rule.id] = {
            "enabled": rule.config.enabled,
            "level": rule.config.level,
        }
        if rule.config.parameters:
            for parameter, value in rule.config.parameters.items():
                config["rule"][rule.id][parameter] = value

    return config


def main():
    # Setup the command line arguments
    args = setup_arg_parser()

    # Fetch the default configuration
    config = get_config()

    # Write to the given file
    try:
        # TODO: check if file already exists and prompt to overwrite
        with open(args.output, "wb") as f:
            tomli_w.dump(config, f)
    except OSError:
        print(f"Error writing to file: {args.output}")
        return 1
    else:
        print(f"Default config written to file: {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
