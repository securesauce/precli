# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 12
# end_column: 16
import ftplib


ftp = ftplib.FTP_TLS(
    "ftp.us.debian.org",
    context=None,
    encoding="utf-8",
)
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
