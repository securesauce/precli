# level: ERROR
# start_line: 13
# end_line: 17
# start_column: 0
# end_column: 1
import argparse


parser = argparse.ArgumentParser(
    prog="ProgramName",
    description="What the program does",
)
parser.add_argument(
    "--api-key",
    dest="api_key",
    help="API key to connect to the server",
)
