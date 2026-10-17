# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 12
# end_column: 15
import hmac
import secrets


key = secrets.token_bytes(nbytes=28)  # suppress: PY028
message = b"Hello, world!"
hmac.digest(key, message, digest="sha256")
