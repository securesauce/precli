# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 9
# end_column: 12
import hmac


key = b"my-super-duper-secret-key"
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="blake2s")
