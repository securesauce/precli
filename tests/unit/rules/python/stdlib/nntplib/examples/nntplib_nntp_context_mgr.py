# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 6
# end_column: 11
import nntplib


with nntplib.NNTP("news.gmane.io") as n:
    n.login("user", "password")
    n.group("gmane.comp.python.committers")
