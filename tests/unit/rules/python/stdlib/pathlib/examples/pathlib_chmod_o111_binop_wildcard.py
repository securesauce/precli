# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 16
# end_column: 20
from pathlib import Path
from stat import *


file_path = Path("/etc/passwd")
mode = S_IXUSR | S_IXGRP | S_IXOTH
file_path.chmod(mode)
