# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 19
# end_column: 23
import os


filename = '/etc/passwd'
mode = 0x1ff
os.chmod(filename, mode)
