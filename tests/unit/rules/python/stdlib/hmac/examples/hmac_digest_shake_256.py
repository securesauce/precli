# level: NONE
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.digest(key, message, digest="shake_256")
