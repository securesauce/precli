# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 6
# end_column: 20
import ftplib


ftp = ftplib.FTP_TLS("ftp.us.debian.org")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
