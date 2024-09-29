# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 64
# end_column: 68
import ssl


cert = ssl.get_server_certificate(("example.com", 443), timeout=None)
