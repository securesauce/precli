# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 19
# end_column: 26
import nntplib


context = None
s = nntplib.NNTP("news.gmane.io")
s.starttls(context=context)
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
