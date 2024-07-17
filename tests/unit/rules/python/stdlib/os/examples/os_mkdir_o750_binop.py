# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 20
# end_column: 24
import os
import stat


path = "examples"
mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
os.mkdir(path, mode=mode)
