import nntplib


s = nntplib.NNTP("news.gmane.io")
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
