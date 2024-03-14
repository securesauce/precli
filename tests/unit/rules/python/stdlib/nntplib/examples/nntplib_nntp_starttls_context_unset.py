# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 0
# end_column: 10
import nntplib


s = nntplib.NNTP("news.gmane.io")
s.starttls()
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
