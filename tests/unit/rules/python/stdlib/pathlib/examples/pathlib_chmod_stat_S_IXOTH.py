# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 16
# end_column: 28
import pathlib
import stat


file_path = pathlib.Path("/etc/passwd")
file_path.chmod(stat.S_IXOTH)
