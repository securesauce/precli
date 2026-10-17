# level: NONE
import getpass
import poplib
import ssl


M = poplib.POP3("localhost", timeout=5)
M.stls(context=ssl.create_default_context())
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
