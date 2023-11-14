# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 37
# end_column: 48
import hmac


key = b"my-secret-key"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="ripemd160")
