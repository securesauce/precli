# level: NONE
import socket
import smtplib
import ssl


socket.setdefaulttimeout(5.0)
server = smtplib.SMTP("smtp.example.com", 587)
server.starttls(context=ssl.create_default_context())
