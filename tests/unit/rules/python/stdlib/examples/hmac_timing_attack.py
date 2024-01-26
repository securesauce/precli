# level: ERROR
# start_line: 18
# end_line: 18
# start_column: 14
# end_column: 16
import hmac


received_digest = (
    b"\xe2\x93\x08\x19T8\xdc\x80\xef\x87\x90m\x1f\x9d\xf7\xf2"
    b"\xf5\x10>\xdbf\xa2\xaf\xf7x\xcdX\xdf"
)

key = b"my-secret-key"
password = b"pass"
digest = hmac.digest(key, password, digest="sha224")

return digest == received_digest
