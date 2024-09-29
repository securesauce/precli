# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 17
# end_column: 44
import poplib
import ssl


pop = poplib.POP3("mail.my-mail-server.com")
pop.stls(ssl.create_default_context())
