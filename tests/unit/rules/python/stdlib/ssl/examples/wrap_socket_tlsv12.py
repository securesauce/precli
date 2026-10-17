# level: NONE
import socket
import ssl


socket = socket.create_connection(("localhost", 443))
ssl.wrap_socket(socket, ssl_version=ssl.PROTOCOL_TLSv1_2)
