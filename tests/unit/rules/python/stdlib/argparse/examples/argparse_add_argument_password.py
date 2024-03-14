# level: ERROR
# start_line: 20
# end_line: 26
# start_column: 0
# end_column: 1
import argparse


parser = argparse.ArgumentParser(
    prog="ProgramName",
    description="What the program does",
)
parser.add_argument(
    "-u",
    "--user",
    dest="user",
    action="store",
    help="user for the database",
)
parser.add_argument(
    "-p",
    "--password",
    dest="password",
    action="store",
    help="password for the database",
)
