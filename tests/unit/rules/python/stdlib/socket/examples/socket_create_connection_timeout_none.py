# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 56
# end_column: 60
import socket


s = socket.create_connection(("127.0.0.1", 80), timeout=None)
s.recv(1024)
s.close()
