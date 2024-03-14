# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 4
# end_column: 20
import nntplib


s = nntplib.NNTP_SSL("news.gmane.io")
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
