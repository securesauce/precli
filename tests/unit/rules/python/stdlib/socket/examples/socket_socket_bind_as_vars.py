# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 7
# end_column: 11
import socket


address = "0.0.0.0"
port = 80
addr = (address, port)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(addr)
