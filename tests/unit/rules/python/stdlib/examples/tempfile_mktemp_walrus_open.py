# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 9
# end_column: 13
import tempfile


if filename := tempfile.mktemp():
    with open(filename, "w+") as f:
        f.write(b"Hello World!\n")
