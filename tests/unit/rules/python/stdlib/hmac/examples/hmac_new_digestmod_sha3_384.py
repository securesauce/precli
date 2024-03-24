# level: NONE
import hmac
import secrets


key = secrets.token_bytes(nbytes=48)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="sha3_384")
