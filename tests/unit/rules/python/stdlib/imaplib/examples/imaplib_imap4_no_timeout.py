# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 20
# end_column: 40
import imaplib
import ssl


imap = imaplib.IMAP4("imap.example.com")
imap.starttls(ssl.create_default_context())
