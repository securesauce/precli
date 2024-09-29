# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 20
# end_column: 79
import nntplib
import ssl


s = nntplib.NNTP_SSL("news.gmane.io", ssl_context=ssl.create_default_context())
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
