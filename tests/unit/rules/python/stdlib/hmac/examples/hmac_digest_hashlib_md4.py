# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 33
# end_column: 44
import hashlib
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.digest(key, message, digest=hashlib.md4)
