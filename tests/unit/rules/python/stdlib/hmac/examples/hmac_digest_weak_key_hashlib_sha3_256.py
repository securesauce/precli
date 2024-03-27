# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 12
# end_column: 15
import hashlib
import hmac
import secrets


key = secrets.token_urlsafe(16)  # suppress: PY028
message = b"Hello, world!"
hmac.digest(key, message, digest=hashlib.sha3_256)
