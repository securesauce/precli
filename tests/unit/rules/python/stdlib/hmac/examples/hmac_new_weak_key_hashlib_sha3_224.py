# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 9
# end_column: 12
import hashlib
import hmac


key = b"my-super-duper-secret"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_224)
