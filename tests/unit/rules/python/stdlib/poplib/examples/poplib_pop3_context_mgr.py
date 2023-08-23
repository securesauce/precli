import poplib


with poplib.POP3("domain.org") as pop3:
    pop3.user("user")
