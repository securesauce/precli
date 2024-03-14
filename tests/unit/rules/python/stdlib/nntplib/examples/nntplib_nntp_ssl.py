# level: NONE
import nntplib
import ssl


s = nntplib.NNTP_SSL("news.gmane.io", context=ssl.create_default_context())
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
