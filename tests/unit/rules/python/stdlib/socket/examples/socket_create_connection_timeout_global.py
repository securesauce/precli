# level: NONE
import socket


socket.setdefaulttimeout(5.0)
s = socket.create_connection(("127.0.0.1", 80))
s.recv(1024)
s.close()
