# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 16
# end_column: 21
from pathlib import Path
from stat import S_IXOTH as IXOTH


file_path = Path("example.sh")
file_path.chmod(IXOTH)
