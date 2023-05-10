

def init_nntp(n):
    n.starttls()


nntp = nntplib.NNTP('news.gmane.io')
init_nntp(nntp)
nntp.login()
