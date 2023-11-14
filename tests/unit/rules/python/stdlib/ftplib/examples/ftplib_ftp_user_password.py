# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 6
# end_column: 16
import ftplib


ftp = ftplib.FTP("ftp.us.debian.org", "user", "password")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
