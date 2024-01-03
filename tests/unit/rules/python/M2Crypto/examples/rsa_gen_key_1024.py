# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 22
# end_column: 26
from M2Crypto import RSA


new_key = RSA.gen_key(1024, 65537)
