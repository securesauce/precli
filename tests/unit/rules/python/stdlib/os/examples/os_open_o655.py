# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 63
# end_column: 68
import os


file_path = 'example.txt'
fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o655)

try:
    os.write(fd, b"Hello, world!\n")
finally:
    os.close(fd)
