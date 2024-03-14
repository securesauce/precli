# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 6
# end_column: 18
import getpass
import imaplib


imap4 = imaplib.IMAP4()
authobject = object()
imap4.authenticate("SKEY", authobject)
imap4.select()
typ, data = imap4.search(None, "ALL")
for num in data[0].split():
    typ, data = imap4.fetch(num, "(RFC822)")
    print(f"Message {num}\n{data[0][1]}\n")
imap4.close()
imap4.logout()
