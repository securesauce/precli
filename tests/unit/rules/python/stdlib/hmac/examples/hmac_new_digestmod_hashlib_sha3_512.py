# level: NONE
import hashlib
import hmac
import secrets


key = secrets.token_bytes(64)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_512)
