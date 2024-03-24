# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 9
# end_column: 12
import hashlib
import hmac
import secrets


key = secrets.token_bytes(nbytes=16)  # suppress: PY028
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod=hashlib.sha3_512)
