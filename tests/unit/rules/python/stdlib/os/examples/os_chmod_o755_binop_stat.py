# level: WARNING
# start_line: 13
# end_line: 14
# start_column: 4
# end_column: 31
import os
import stat


# 0o755 for rwxr-xr-x
os.chmod(
    "example.txt",
    stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRGRP | stat.S_IXGRP |
    stat.S_IROTH | stat.S_IXOTH,
)
