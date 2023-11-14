# level: NONE
import getpass
import poplib


M = poplib.POP3_SSL("localhost")
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
