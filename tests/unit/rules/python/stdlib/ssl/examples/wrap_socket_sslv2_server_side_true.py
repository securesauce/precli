import socket
import ssl


socket = socket.create_connection(("localhost", 443))
ssl.wrap_socket(socket, ssl_version=ssl.PROTOCOL_SSLv2, server_side=True)
