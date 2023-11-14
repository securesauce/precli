# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 4
# end_column: 8
import tempfile


filename = tempfile.mktemp()
f = open(filename, "w+")
f.write(b"Hello World!\n")
f.close()
