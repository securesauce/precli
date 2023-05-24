import ftplib


with ftplib.FTP("ftp.us.debian.org") as ftp:
    ftp.cwd("debian")
    ftp.retrlines("LIST")
