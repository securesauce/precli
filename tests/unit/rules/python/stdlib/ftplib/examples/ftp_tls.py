# level: NONE
from ftplib import FTP


ftp = FTP_TLS("ftp.us.debian.org")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
