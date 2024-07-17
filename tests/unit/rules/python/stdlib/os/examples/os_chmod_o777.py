# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 19
# end_column: 23
import os


filename = '/etc/passwd'
mode = 0o777
os.chmod(filename, mode)
