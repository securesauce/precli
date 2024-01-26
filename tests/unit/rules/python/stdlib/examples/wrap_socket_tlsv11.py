# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 40
# end_column: 56
import socket
import ssl


socket = socket.create_connection(("localhost", 443))
ssl.wrap_socket(socket, ssl_version=ssl.PROTOCOL_TLSv1_1)
