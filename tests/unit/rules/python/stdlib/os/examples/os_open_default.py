# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 12
# end_column: 62
import os


file_path = 'example.txt'
fd = os.open(file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)

try:
    os.write(fd, b"Hello, world!\n")
finally:
    os.close(fd)
