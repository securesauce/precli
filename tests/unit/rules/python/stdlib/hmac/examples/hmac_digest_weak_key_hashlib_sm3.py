# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 12
# end_column: 15
import hashlib
import hmac


key = b"abcdefghijklmnop"
message = b"Hello, world!"
hmac.digest(key, message, digest=hashlib.sm3)
