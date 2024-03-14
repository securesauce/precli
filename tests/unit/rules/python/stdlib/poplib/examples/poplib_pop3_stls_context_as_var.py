# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 15
# end_column: 22
import getpass
import poplib


context = None
M = poplib.POP3("localhost")
M.stls(context=context)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
