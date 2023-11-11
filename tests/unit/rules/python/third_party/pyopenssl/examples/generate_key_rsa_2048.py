from OpenSSL import crypto


crypto.PKey().generate_key(type=crypto.TYPE_RSA, bits=2048)
