# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 20
# end_column: 25
import hashlib


our_app_iters = 500_000
hashlib.pbkdf2_hmac("sha", b"password", b"bad salt" * 2, our_app_iters)
