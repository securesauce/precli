# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 41
# end_column: 48
import getpass
import poplib


context = None
M = poplib.POP3_SSL("localhost", context=context)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
