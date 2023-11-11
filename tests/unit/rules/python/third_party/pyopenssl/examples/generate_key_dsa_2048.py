from OpenSSL import crypto


crypto.PKey().generate_key(type=crypto.TYPE_DSA, bits=2048)
