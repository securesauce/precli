# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 42
# end_column: 46
import nntplib
import ssl


s = nntplib.NNTP("news.gmane.io", timeout=None)
s.starttls(context=ssl.create_default_context())
s.login("user", "password")
f = open("article.txt", "rb")
s.post(f)
s.quit()
