# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 9
# end_column: 12
import hmac
from secrets import token_bytes


key = token_bytes(nbytes=None)
message = b"Hello, world!"
hmac.new(key, msg=message, digestmod="sha384")
