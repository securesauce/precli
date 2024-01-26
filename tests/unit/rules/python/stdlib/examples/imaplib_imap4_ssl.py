# level: NONE
import getpass
import imaplib


imap4 = imaplib.IMAP4_SSL()
imap4.login(getpass.getuser(), getpass.getpass())
imap4.select()
typ, data = imap4.search(None, "ALL")
for num in data[0].split():
    typ, data = imap4.fetch(num, "(RFC822)")
    print(f"Message {num}\n{data[0][1]}\n")
imap4.close()
imap4.logout()
