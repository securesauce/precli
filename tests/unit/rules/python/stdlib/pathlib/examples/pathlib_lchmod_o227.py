# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 22
# end_column: 26
from pathlib import Path


mode = 0o227
file_path = Path('/etc/passwd')
file_path.lchmod(mode=mode)
