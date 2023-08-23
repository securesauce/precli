import imaplib


with imaplib.IMAP4("domain.org") as imap4:
    imap4.noop()
    imap4.login("user", "password")
