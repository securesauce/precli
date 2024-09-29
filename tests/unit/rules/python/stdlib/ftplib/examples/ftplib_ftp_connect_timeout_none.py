# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 46
# end_column: 50
import ftplib


ftp_server = ftplib.FTP()
ftp_server.connect("ftp.example.com", timeout=None)
