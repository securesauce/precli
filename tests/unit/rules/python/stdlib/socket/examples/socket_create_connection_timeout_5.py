# level: NONE
import socket


s = socket.create_connection(("127.0.0.1", 80), timeout=5)
s.recv(1024)
s.close()
