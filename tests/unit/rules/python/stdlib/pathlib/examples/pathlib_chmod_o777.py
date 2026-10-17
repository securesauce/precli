# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 21
# end_column: 25
import pathlib


filename = "/etc/passwd"
mode = 0o777
file_path = pathlib.Path(filename)
file_path.chmod(mode=mode)
