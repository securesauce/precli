# level: NONE
import ftplib


ftp = ftplib.FTP_TLS("ftp.us.debian.org")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
