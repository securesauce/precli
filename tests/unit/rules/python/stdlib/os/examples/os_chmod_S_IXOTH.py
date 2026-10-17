# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 24
# end_column: 31
import os
from stat import S_IXOTH


os.chmod("/etc/passwd", S_IXOTH)
