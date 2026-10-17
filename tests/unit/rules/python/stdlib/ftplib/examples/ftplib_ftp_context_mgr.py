# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 5
# end_column: 15
import ftplib


with ftplib.FTP("ftp.us.debian.org") as ftp:
    ftp.cwd("debian")
    ftp.retrlines("LIST")
