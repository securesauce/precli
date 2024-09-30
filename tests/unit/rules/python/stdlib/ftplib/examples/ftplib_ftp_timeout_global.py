# level: NONE
import ftplib
import socket


socket.setdefaulttimeout(5.0)
ftp_server = ftplib.FTP("ftp.example.com")
