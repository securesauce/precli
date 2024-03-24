# level: NONE
import hmac


key = b"my-super-duper-secret-key-string"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="sha3_224")
