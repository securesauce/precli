# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 21
# end_column: 25
from pathlib import *
import stat


file_path = Path("example.txt")
mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
file_path.touch(mode=mode)
