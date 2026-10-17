# level: NONE
import socket
import telnetlib


socket.setdefaulttimeout(5.0)
telnet = telnetlib.Telnet("example.com", 23)
