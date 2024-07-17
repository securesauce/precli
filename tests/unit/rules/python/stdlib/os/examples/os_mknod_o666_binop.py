# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 25
# end_column: 29
import os
import stat


file_path = "my_regular_file"
mode = 0o666 | stat.S_IFREG
os.mknod(file_path, mode=mode)
