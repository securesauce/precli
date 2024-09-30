# level: NONE
import imaplib
import socket
import ssl


socket.setdefaulttimeout(5.0)
imap = imaplib.IMAP4("imap.example.com", timeout=5)
imap.starttls(ssl.create_default_context())
