# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 28
# end_column: 47
import socket


s = socket.create_connection(("127.0.0.1", 80))
s.recv(1024)
s.close()
