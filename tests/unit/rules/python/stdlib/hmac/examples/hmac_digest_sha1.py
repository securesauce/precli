# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 33
# end_column: 39
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.digest(key, message, digest="sha1")
