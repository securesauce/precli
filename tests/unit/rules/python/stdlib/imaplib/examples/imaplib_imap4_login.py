# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 6
# end_column: 11
import getpass
import imaplib


imap4 = imaplib.IMAP4()
imap4.login(getpass.getuser(), getpass.getpass())
imap4.select()
typ, data = imap4.search(None, "ALL")
for num in data[0].split():
    typ, data = imap4.fetch(num, "(RFC822)")
    print(f"Message {num}\n{data[0][1]}\n")
imap4.close()
imap4.logout()
