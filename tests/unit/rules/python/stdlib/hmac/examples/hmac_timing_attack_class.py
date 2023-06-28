import hmac


received_digest = (
    b"\xe2\x93\x08\x19T8\xdc\x80\xef\x87\x90m\x1f\x9d\xf7\xf2"
    b"\xf5\x10>\xdbf\xa2\xaf\xf7x\xcdX\xdf"
)

key = b"my-secret-key"
password = b"pass"
h = hmac.HMAC(key, msg=password, digestmod="sha224")
digest = h.digest()

return digest == received_digest
