# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 41
# end_column: 45
import getpass
import poplib


M = poplib.POP3_SSL("localhost", context=None)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
