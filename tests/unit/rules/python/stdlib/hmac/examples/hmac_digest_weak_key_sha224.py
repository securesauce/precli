# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 12
# end_column: 15
import hmac
import secrets


key_size = 16
key = secrets.token_bytes(nbytes=key_size)  # suppress: PY028
message = b"Hello, world!"
hmac.digest(key, message, digest="sha224")
