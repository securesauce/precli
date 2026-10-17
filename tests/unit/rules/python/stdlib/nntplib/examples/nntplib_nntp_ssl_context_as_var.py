# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 50
# end_column: 57
import nntplib


context = None
s = nntplib.NNTP_SSL("news.gmane.io", ssl_context=context, timeout=5)
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
