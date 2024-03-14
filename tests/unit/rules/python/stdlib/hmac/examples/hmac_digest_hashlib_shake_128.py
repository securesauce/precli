# level: NONE
import hashlib
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.digest(key, message, digest=hashlib.shake_128)
