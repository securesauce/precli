# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 12
# end_column: 19
import ftplib


context = None
ftp = ftplib.FTP_TLS(
    "ftp.us.debian.org",
    context=context,
    encoding="utf-8",
)
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
