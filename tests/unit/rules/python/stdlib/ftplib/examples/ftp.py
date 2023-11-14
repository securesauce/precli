# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 6
# end_column: 9
from ftplib import FTP


ftp = FTP("ftp.us.debian.org")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
