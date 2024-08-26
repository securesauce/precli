# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 16
# end_column: 20
from pathlib import Path


filename = '/etc/passwd'
mode = 0x1ff
file_path = Path(filename)
file_path.chmod(mode)
