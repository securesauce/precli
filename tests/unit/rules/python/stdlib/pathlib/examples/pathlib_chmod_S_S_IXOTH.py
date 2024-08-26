# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 16
# end_column: 25
import pathlib
import stat as S


file_path = pathlib.Path("/etc/passwd")
file_path.chmod(S.S_IXOTH)
