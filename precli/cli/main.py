# Copyright 2023 Secure Saurce LLC
import argparse
import io
import logging
import os
import pathlib
import sys
import traceback

from ignorelib import IgnoreFilterManager
from rich import progress

import precli
from precli.core import loader
from precli.core.level import Level
from precli.core.metrics import Metrics
from precli.core.result import Result
from precli.renderers.detailed import Detailed
from precli.renderers.json import Json
from precli.renderers.plain import Plain


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50


def _init_logger(log_level=logging.INFO):
    """Initialize the logger.

    :param debug: Whether to enable debug mode
    :return: An instantiated logging instance
    """
    LOG.handlers = []
    logging.captureWarnings(True)
    LOG.setLevel(log_level)
    handler = logging.StreamHandler(sys.stderr)
    LOG.addHandler(handler)
    LOG.debug("logging initialized")


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


def build_ignore_mgr(path: str, ignore_file: str) -> IgnoreFilterManager:
    return IgnoreFilterManager.build(
        path,
        global_ignore_file_paths=[],
        global_patterns=[],
        ignore_file_name=ignore_file,
    )


def discover_files(targets: list[str], recursive: bool):
    file_list = []

    for fname in targets:
        if os.path.isdir(fname):
            gitignore_mgr = build_ignore_mgr(fname, ".gitignore")
            preignore_mgr = build_ignore_mgr(fname, ".preignore")

            if recursive is True:
                for root, _, files in gitignore_mgr.walk():
                    for file in files:
                        path = os.path.join(root, file)
                        if not preignore_mgr.is_ignored(path):
                            file_list.append(path)
            else:
                files = os.listdir(path=fname)
                for file in files:
                    path = os.path.join(fname, file)
                    if not (
                        gitignore_mgr.is_ignored(path)
                        or preignore_mgr.is_ignored(path)
                    ):
                        file_list.append(path)
        else:
            file_list.append(fname)
    return file_list


def run_checks(parsers: dict, file_list: list[str]) -> list[Result]:
    """Runs through all files in the scope

    :return: -
    """
    # if we have problems with a file, we'll remove it from the file_list
    # and add it to the skipped list instead
    new_file_list = list(file_list)
    files_skipped = []
    if (
        len(file_list) > PROGRESS_THRESHOLD
        and LOG.getEffectiveLevel() <= logging.INFO
    ):
        files = progress.track(file_list)
    else:
        files = file_list

    results = []
    lines = 0
    for fname in files:
        try:
            if fname == "-":
                open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
                fdata = io.BytesIO(open_fd.read())
                new_file_list = [
                    "<stdin>" if x == "-" else x for x in new_file_list
                ]
                results += parse_file(
                    parsers, "<stdin>", fdata, new_file_list, files_skipped
                )
            else:
                with open(fname, "rb") as fdata:
                    lines += sum(1 for _ in fdata)
                with open(fname, "rb") as fdata:
                    results += parse_file(
                        parsers, fname, fdata, new_file_list, files_skipped
                    )
        except OSError as e:
            files_skipped.append((fname, e.strerror))
            new_file_list.remove(fname)

    metrics = Metrics(
        files=len(new_file_list),
        files_skipped=len(files_skipped),
        lines=lines,
        errors=sum(result.level == Level.ERROR for result in results),
        warnings=sum(result.level == Level.WARNING for result in results),
        notes=sum(result.level == Level.NOTE for result in results),
    )

    return results, metrics


def parse_file(
    parsers: dict,
    fname: str,
    fdata: io.BufferedReader,
    new_file_list: list,
    files_skipped: list,
) -> list[Result]:
    try:
        data = fdata.read()
        file_extension = pathlib.Path(fname).suffix
        if file_extension in parsers.keys():
            LOG.debug("working on file : %s", fname)
            parser = parsers[file_extension]
            return parser.parse(fname, data)
    except KeyboardInterrupt:
        sys.exit(2)
    except SyntaxError as e:
        print(
            f"Syntax error while parsing file. ({e.filename}, "
            f"line {e.lineno})",
            file=sys.stderr,
        )
        files_skipped.append((fname, e))
        new_file_list.remove(fname)
    except Exception as e:
        LOG.error(
            f"Exception occurred when executing rules against "
            f'{fname}. Run "precli --debug {fname}" to see the full '
            f"traceback."
        )
        files_skipped.append((fname, "Exception while parsing file"))
        new_file_list.remove(fname)
        LOG.debug(f"  Exception string: {e}")
        LOG.debug(f"  Exception traceback: {traceback.format_exc()}")
    return []


def main():
    debug = (
        logging.DEBUG
        if "-d" in sys.argv or "--debug" in sys.argv
        else logging.INFO
    )
    _init_logger(debug)

    # Setup the command line arguments
    args = setup_arg_parser()

    enabled = args.enable.split(",") if args.enable else []
    disabled = args.disable.split(",") if args.disable else []
    parsers = loader.load_parsers(enabled, disabled)

    # Compile a list of the targets
    file_list = discover_files(args.targets, args.recursive)

    results, metrics = run_checks(parsers, file_list)

    if args.json is True:
        json = Json(args.no_color)
        json.render(results, metrics)
    elif args.plain is True:
        plain = Plain(args.no_color)
        plain.render(results, metrics)
    else:
        detailed = Detailed(args.no_color)
        detailed.render(results, metrics)


if __name__ == "__main__":
    main()
