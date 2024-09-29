# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 33
# end_column: 55
import ssl


cert = ssl.get_server_certificate(("example.com", 443))
