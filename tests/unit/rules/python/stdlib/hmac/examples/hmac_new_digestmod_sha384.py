# level: NONE
import hmac
from secrets import token_bytes


key = token_bytes(nbytes=48)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="sha384")
