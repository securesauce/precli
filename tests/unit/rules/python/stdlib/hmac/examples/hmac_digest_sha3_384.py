# level: NONE
import hmac
import secrets


key = secrets.token_bytes(nbytes=48)
message = b"Hello, world!"
hmac.digest(key, message, digest="sha3_384")
