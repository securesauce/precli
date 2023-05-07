# Copyright 2023 Secure Saurce LLC
import argparse
import io
import logging
import os
import pathlib
import sys
import traceback
from importlib.metadata import entry_points

from rich import console
from rich import progress
from rich import syntax

import precli
from precli.core.level import Level
from precli.core.result import Result
from precli.core.result import Rule


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50

parsers = {}
console = console.Console(highlight=False)


def setup_arg_parser():
    parser = argparse.ArgumentParser(
        description="precli - a static analysis security tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "targets",
        metavar="targets",
        type=str,
        nargs="*",
        help="source file(s) or directory(s) to be tested",
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


def discover_files(targets: list[str]):
    files_list = []
    for fname in targets:
        if os.path.isdir(fname):
            # TODO
            print("skip")
        else:
            files_list.append(fname)
    return files_list


def run_checks(files_list: list[str]):
    """Runs through all files in the scope

    :return: -
    """
    # if we have problems with a file, we'll remove it from the files_list
    # and add it to the skipped list instead
    new_files_list = list(files_list)
    if (
        len(files_list) > PROGRESS_THRESHOLD
        and LOG.getEffectiveLevel() <= logging.INFO
    ):
        files = progress.track(files_list)
    else:
        files = files_list

    for fname in files:
        LOG.debug("working on file : %s", fname)

        results = []
        try:
            if fname == "-":
                open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
                fdata = io.BytesIO(open_fd.read())
                new_files_list = [
                    "<stdin>" if x == "-" else x for x in new_files_list
                ]
                results = parse_file("<stdin>", fdata, new_files_list)
            else:
                with open(fname, "rb") as fdata:
                    results = parse_file(fname, fdata, new_files_list)
        except OSError:
            # self.skipped.append((fname, e.strerror))
            new_files_list.remove(fname)

        for result in results:
            rule = Rule.get_by_id(result.rule_id)
            match result.level:
                case Level.ERROR:
                    emoji = ":stop_sign-emoji:"
                    style = "red"

                case Level.WARNING:
                    emoji = ":warning-emoji:"
                    style = "yellow"

                case Level.NOTE:
                    emoji = ":information-emoji:"
                    style = "blue"

            console.print(
                f"{emoji}  {result.level.name.title()} on line "
                f"{result.location.start_line} in {result.location.file_name}",
                style=style,
                markup=False,
            )
            console.print(
                f"{rule.id}: {rule.cwe.name}",
                style=style,
            )
            console.print(
                f"{result.message}",
                style=style,
            )
            code = syntax.Syntax.from_path(
                result.location.file_name,
                line_numbers=True,
                line_range=(
                    result.location.start_line - 1,
                    result.location.end_line + 1,
                ),
                highlight_lines=(
                    result.location.start_line,
                    result.location.end_line,
                ),
            )
            console.print(code)
            console.print()


def parse_file(
    fname: str, fdata: io.BufferedReader, new_files_list: list
) -> list[Result]:
    try:
        data = fdata.read()
        file_extension = pathlib.Path(fname).suffix
        if file_extension in parsers.keys():
            parser = parsers[file_extension]
            return parser.parse(fname, data)
    except KeyboardInterrupt:
        sys.exit(2)
    except SyntaxError as e:
        print(e)
        # self.skipped.append(
        #    (fname, "syntax error while parsing AST from file")
        # )
        new_files_list.remove(fname)
    except Exception as e:
        print(traceback.format_exc())
        LOG.error(
            "Exception occurred when executing tests against "
            '%s. Run "precli --debug %s" to see the full '
            "traceback.",
            fname,
            fname,
        )
        # self.skipped.append((fname, "exception while scanning file"))
        new_files_list.remove(fname)
        LOG.debug("  Exception string: %s", e)
        LOG.debug("  Exception traceback: %s", traceback.format_exc())


def main():
    # Setup the command line arguments
    args = setup_arg_parser()

    discovered_plugins = entry_points(group="precli.parsers")
    for plugin in discovered_plugins:
        parser = plugin.load()()
        parsers[parser.file_extension()] = parser

    # Compile a list of the targets
    files_list = discover_files(args.targets)

    run_checks(files_list)


if __name__ == "__main__":
    main()
