# level: ERROR
# start_line: 16
# end_line: 16
# start_column: 13
# end_column: 15
import hmac


received_digest = "e29308195438dc80ef87906d1f9df7f2f5103edb66a2aff778cd58df"

key = b"my-secret-key"
password = b"pass"
h = hmac.HMAC(key, msg=password, digestmod="sha224")
digest = h.hexdigest()

print(digest == received_digest)
