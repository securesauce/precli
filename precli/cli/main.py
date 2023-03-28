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
from stevedore import extension

import precli


LOG = logging.getLogger(__name__)
PROGRESS_THRESHOLD = 50

parsers = {}

def traverse_tree(tree):
    cursor = tree.walk()

    reached_root = False
    while reached_root is False:
        yield cursor.node

        if cursor.goto_first_child():
            continue

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True

            if cursor.goto_next_sibling():
                retracing = False


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
        version="%(prog)s {version}\n  python version = {python}".format(
            version=precli.__version__, python=python_ver
        ),
    )
    args = parser.parse_args()

    if not args.targets:
        parser.print_usage()
        sys.exit(2)

    return args


def discover_files(targets):
    files_list = []
    for fname in targets:
        if os.path.isdir(fname):
            # TODO
            print("skip")
        else:
            files_list.append(fname)
    return files_list


def run_checks(files_list):
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

        try:
            if fname == "-":
                open_fd = os.fdopen(sys.stdin.fileno(), "rb", 0)
                fdata = io.BytesIO(open_fd.read())
                new_files_list = [
                    "<stdin>" if x == "-" else x for x in new_files_list
                ]
                parse_file("<stdin>", fdata, new_files_list)
            else:
                with open(fname, "rb") as fdata:
                    parse_file(fname, fdata, new_files_list)
        except OSError as e:
            # self.skipped.append((fname, e.strerror))
            new_files_list.remove(fname)


def format_captures(tree, captures):
    for c in captures:
        node = c[0]
        print(node.text)
        print(node.start_point)
        print(node.end_point)


def parse_file(fname, fdata, new_files_list):
    try:
        # parse the current file
        data = fdata.read()
        # lines = data.splitlines()
        # self.metrics.begin(fname)
        # self.metrics.count_locs(lines)
        # nosec_lines is a dict of line number -> set of tests to ignore
        #                                         for the line
        # nosec_lines = dict()
        # try:
        #    fdata.seek(0)
        #    tokens = tokenize.tokenize(fdata.readline)

        #    if not self.ignore_nosec:
        #        for toktype, tokval, (lineno, _), _, _ in tokens:
        #            if toktype == tokenize.COMMENT:
        #                nosec_lines[lineno] = _parse_nosec_comment(tokval)

        # except tokenize.TokenError:
        #    pass
        # score = self._execute_ast_visitor(fname, fdata, data, nosec_lines)
        # self.scores.append(score)
        # self.metrics.count_issues([score])

        file_extension = pathlib.Path(fname).suffix
        if file_extension in parsers.keys():
            parser = parsers[file_extension]
            # tree = parser.parse(data)
            parser.parse(data)

            # for node in traverse_tree(tree):
            #    print(node)

    except KeyboardInterrupt:
        sys.exit(2)
    except SyntaxError as e:
        print(e)
        # self.skipped.append(
        #    (fname, "syntax error while parsing AST from file")
        # )
        new_files_list.remove(fname)
    except Exception as e:
        print(e)
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
