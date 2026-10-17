# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 24
# end_column: 29
import os
from stat import S_IXOTH as IXOTH


os.chmod("/etc/passwd", IXOTH)
