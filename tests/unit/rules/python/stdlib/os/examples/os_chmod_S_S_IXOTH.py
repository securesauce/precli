# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 24
# end_column: 33
import os
import stat as S


os.chmod("/etc/passwd", S.S_IXOTH)
