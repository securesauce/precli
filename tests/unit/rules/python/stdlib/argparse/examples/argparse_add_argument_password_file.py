# level: NONE
import argparse


parser = argparse.ArgumentParser(
    prog="ProgramName",
    description="What the program does",
)
parser.add_argument(
    "--user",
    dest="user",
    action="store",
    help="user for the database",
)
parser.add_argument(
    "--password-file",
    dest="password_file",
    action="store",
    type=argparse.FileType("w", encoding="utf-8"),
    help="password file to load",
)
