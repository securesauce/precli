# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 46
# end_column: 53
import nntplib


context = None
s = nntplib.NNTP_SSL("news.gmane.io", context=context)
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
