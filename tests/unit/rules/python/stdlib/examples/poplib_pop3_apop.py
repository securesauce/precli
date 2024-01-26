# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 2
# end_column: 6
import getpass
import poplib


M = poplib.POP3("localhost")
secret = getpass.getpass()
M.apop(getpass.getuser(), secret)
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
