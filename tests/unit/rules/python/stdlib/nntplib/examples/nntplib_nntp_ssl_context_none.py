# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 46
# end_column: 50
import nntplib


s = nntplib.NNTP_SSL("news.gmane.io", context=None)
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
