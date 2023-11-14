# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 5
# end_column: 9
import tempfile


filename = tempfile.mktemp()
with open(filename, "w+") as f:
    f.write(b"Hello World!\n")
