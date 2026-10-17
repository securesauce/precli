# level: NONE
import imaplib
import ssl


imap = imaplib.IMAP4("imap.example.com", timeout=5)
imap.starttls(ssl.create_default_context())
