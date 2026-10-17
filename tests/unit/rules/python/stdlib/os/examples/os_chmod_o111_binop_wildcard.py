# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 24
# end_column: 28
import os
from stat import *


mode = S_IXUSR | S_IXGRP | S_IXOTH
os.chmod("/etc/passwd", mode)
