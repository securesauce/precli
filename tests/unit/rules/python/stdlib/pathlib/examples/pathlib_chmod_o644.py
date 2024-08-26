# level: NONE
import pathlib


file_path = pathlib.Path("/etc/passwd")
file_path.chmod(0o644)
