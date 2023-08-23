import nntplib


with nntplib.NNTP("news.gmane.io") as n:
    n.login("user", "password")
    n.group("gmane.comp.python.committers")
