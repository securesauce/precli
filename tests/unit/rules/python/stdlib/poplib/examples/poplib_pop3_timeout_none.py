# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 63
# end_column: 67
import getpass
import poplib
import ssl


M = poplib.POP3_SSL(
    "localhost", context=ssl.create_default_context(), timeout=None
)
M.user(getpass.getuser())
M.pass_(getpass.getpass())
numMessages = len(M.list()[1])
for i in range(numMessages):
    for j in M.retr(i + 1)[1]:
        print(j)
