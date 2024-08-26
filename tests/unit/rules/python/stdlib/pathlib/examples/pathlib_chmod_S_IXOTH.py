# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 16
# end_column: 23
import pathlib
from stat import S_IXOTH


file_path = pathlib.Path("/etc/passwd")
file_path.chmod(S_IXOTH)
