# level: NONE
import nntplib
import socket
import ssl


socket.setdefaulttimeout(5.0)
s = nntplib.NNTP("news.gmane.io", timeout=None)
s.starttls(context=ssl.create_default_context())
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
