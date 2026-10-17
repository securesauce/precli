# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 23
# end_column: 34
import ssl


context = ssl.SSLContext()
context.set_ecdh_curve("sect163k1")
