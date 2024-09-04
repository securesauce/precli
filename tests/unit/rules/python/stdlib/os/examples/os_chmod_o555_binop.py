# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 27
# end_column: 31
import os
import stat


mode = 0o777 & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
os.chmod("my_secret_file", mode)
