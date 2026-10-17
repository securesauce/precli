# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 24
# end_column: 36
import os
import stat


os.chmod("/etc/passwd", stat.S_IXOTH)
