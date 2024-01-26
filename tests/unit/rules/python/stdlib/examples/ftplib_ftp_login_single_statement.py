import ftplib


ftplib.FTP("ftp.us.debian.org").login("user", "password").quit()
