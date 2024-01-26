# level: NONE
import nntplib


s = nntplib.NNTP_SSL("news.gmane.io")
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
