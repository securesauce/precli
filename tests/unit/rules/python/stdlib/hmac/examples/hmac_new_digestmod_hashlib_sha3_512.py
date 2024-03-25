# level: NONE
import hashlib
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_512)
