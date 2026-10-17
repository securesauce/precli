# level: NONE
import hashlib
import hmac
import secrets


key = secrets.token_bytes(nbytes=48)
message = b"Hello, world!"
hmac.digest(key, message, digest=hashlib.sha3_384)
