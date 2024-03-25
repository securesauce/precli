# level: ERROR
# start_line: 12
# end_line: 12
# start_column: 37
# end_column: 48
import hashlib
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.md5)
