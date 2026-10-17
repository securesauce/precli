# level: NONE
import hmac


key = b"my-super-duper-secret-key-string"
message = b"Hello, world!"
hmac.digest(key, message, digest="blake2s")
