import getpass
import poplib


M = poplib.POP3("localhost")
M.user(getpass.getuser())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
