# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 54
# end_column: 58
from OpenSSL import crypto


crypto.PKey().generate_key(type=crypto.TYPE_DSA, bits=1024)
