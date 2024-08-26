# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 21
# end_column: 25
from pathlib import Path
import stat


path = "examples"
mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP
file_path = Path(path)
file_path.mkdir(mode=mode)
