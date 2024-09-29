# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 10
# end_column: 15
import imaplib


with imaplib.IMAP4("domain.org", timeout=5) as imap4:
    imap4.noop()
    imap4.login("user", "password")
