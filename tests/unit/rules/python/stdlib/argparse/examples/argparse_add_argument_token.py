# level: ERROR
# start_line: 13
# end_line: 18
# start_column: 0
# end_column: 1
import argparse


parser = argparse.ArgumentParser(
    prog="ProgramName",
    description="What the program does",
)
parser.add_argument(
    "--token",
    dest="api_key",
    action="store",
    help="Token to connect to the server",
)
