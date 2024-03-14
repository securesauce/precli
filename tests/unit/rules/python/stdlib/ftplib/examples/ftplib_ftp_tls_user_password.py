# level: NONE
import ftplib
import ssl


ftp = ftplib.FTP_TLS(
    "ftp.us.debian.org",
    "user",
    "password",
    context=ssl.create_default_context(),
)
ftp.login()

ftp.cwd("debian")
ftp.retrlines("LIST")

ftp.quit()
