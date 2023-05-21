import ftplib


ftp = ftplib.FTP("ftp.us.debian.org", "user", "password")
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
