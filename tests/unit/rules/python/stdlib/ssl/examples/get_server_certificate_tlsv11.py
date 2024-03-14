# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 40
# end_column: 56
import ssl


ssl.get_server_certificate(
    ("localhost", 443), ssl_version=ssl.PROTOCOL_TLSv1_1
)
