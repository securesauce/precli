# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 16
# end_column: 21
import pathlib


file_path = pathlib.Path("/etc/passwd")
file_path.chmod(0o760)
