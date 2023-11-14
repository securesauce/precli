# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 9
# end_column: 13
import poplib


with poplib.POP3("domain.org") as pop3:
    pop3.user("user")
