# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 7
# end_column: 11
import socket


addr = ("0.0.0.0", 80)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(addr)
