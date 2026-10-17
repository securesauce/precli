# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 9
# end_column: 12
import hmac
import secrets


key = secrets.token_bytes(nbytes=16)  # suppress: PY028
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="sha512_256")
