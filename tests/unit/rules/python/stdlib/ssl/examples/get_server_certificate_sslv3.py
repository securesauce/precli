# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 63
# end_column: 77
import ssl


ssl.get_server_certificate(("localhost", 443), ssl_version=ssl.PROTOCOL_SSLv3)
