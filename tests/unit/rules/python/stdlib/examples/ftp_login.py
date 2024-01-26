from ftplib import FTP


ftp = FTP("ftp.us.debian.org")
ftp.login("user", "password")

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
