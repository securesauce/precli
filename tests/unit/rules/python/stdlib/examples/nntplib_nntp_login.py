# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 2
# end_column: 7
import nntplib


s = nntplib.NNTP("news.gmane.io")
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
