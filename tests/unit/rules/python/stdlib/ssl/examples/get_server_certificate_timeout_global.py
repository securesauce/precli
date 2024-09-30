# level: NONE
import socket
import ssl


socket.setdefaulttimeout(5.0)
cert = ssl.get_server_certificate(("example.com", 443))
