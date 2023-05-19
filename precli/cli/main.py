# Copyright 2023 Secure Saurce LLC
import argparse
import io
import logging
import os
import pathlib
import sys
import traceback
from importlib.metadata import entry_points

from rich import progress

import precli
from precli.core.result import Result
from precli.renderers.detailed import Detailed
from precli.renderers.json import Json
from precli.renderers.plain import Plain


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50

parsers = {}


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
    parser.add_argument(
        "-r",
        "--recursive",
        dest="recursive",
        action="store_true",
        help="find and process files in subdirectories",
    )
    parser.add_argument(
        "--json",
        dest="json",
        action="store_true",
        help="display output as formatted JSON",
    )
    parser.add_argument(
        "--plain",
        dest="plain",
        action="store_true",
        help="display output in plain, tabular text",
    )
    parser.add_argument(
        "--no-color",
        dest="no_color",
        action="store_true",
        help="do not display color in output",
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


def discover_files(targets: list[str], recursive: bool):
    file_list = []
    for fname in targets:
        if os.path.isdir(fname):
            if recursive is True:
                for root, _, files in os.walk(fname):
                    for file in files:
                        file_list.append(os.path.join(root, file))
            else:
                files = os.listdir(path=fname)
                for file in files:
                    file_list.append(os.path.join(fname, file))
        else:
            file_list.append(fname)
    return file_list


def run_checks(file_list: list[str]) -> list[Result]:
    """Runs through all files in the scope

    :return: -
    """
    # if we have problems with a file, we'll remove it from the file_list
    # and add it to the skipped list instead
    new_file_list = list(file_list)
    if (
        len(file_list) > PROGRESS_THRESHOLD
        and LOG.getEffectiveLevel() <= logging.INFO
    ):
        files = progress.track(file_list)
    else:
        files = file_list

    results = []
    for fname in files:
        LOG.debug("working on file : %s", fname)

        try:
            if fname == "-":
                open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
                fdata = io.BytesIO(open_fd.read())
                new_file_list = [
                    "<stdin>" if x == "-" else x for x in new_file_list
                ]
                results += parse_file("<stdin>", fdata, new_file_list)
            else:
                with open(fname, "rb") as fdata:
                    results += parse_file(fname, fdata, new_file_list)
        except OSError:
            # self.skipped.append((fname, e.strerror))
            new_file_list.remove(fname)
    return results


def parse_file(
    fname: str, fdata: io.BufferedReader, new_file_list: list
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
        new_file_list.remove(fname)
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
        new_file_list.remove(fname)
        LOG.debug("  Exception string: %s", e)
        LOG.debug("  Exception traceback: %s", traceback.format_exc())
    return []


def main():
    # Setup the command line arguments
    args = setup_arg_parser()

    discovered_plugins = entry_points(group="precli.parsers")
    for plugin in discovered_plugins:
        parser = plugin.load()()
        parsers[parser.file_extension()] = parser

    # Compile a list of the targets
    file_list = discover_files(args.targets, args.recursive)

    results = run_checks(file_list)

    if args.json is True:
        json = Json(args.no_color)
        json.render(results)
    elif args.plain is True:
        plain = Plain(args.no_color)
        plain.render(results)
    else:
        detailed = Detailed(args.no_color)
        detailed.render(results)


if __name__ == "__main__":
    main()
