# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 5
# end_column: 8
from ftplib import FTP


with FTP("ftp.us.debian.org"):
    print("FTP protocol available")
