# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 27
# end_column: 31
import os
import stat


mode = 0o777
mode &= ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
os.chmod("my_secret_file", mode)
