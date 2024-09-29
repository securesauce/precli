# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 79
# end_column: 83
import getpass
import poplib
import ssl


M = poplib.POP3_SSL("localhost", context=ssl.create_default_context(), timeout=None)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
