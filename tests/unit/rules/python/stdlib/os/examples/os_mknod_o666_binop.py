# level: NONE
import os
import stat


file_path = "my_regular_file"
mode = 0o666 | stat.S_IFREG
os.mknod(file_path, mode=mode)
