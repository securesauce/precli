# level: NONE
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
    action="store_true",
    help="password for the database",
)
