# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 30
# end_column: 34
import os


mode = 0o227
os.lchmod('/etc/passwd', mode=mode)
