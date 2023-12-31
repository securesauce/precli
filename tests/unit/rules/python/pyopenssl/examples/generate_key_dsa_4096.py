# level: NONE
from OpenSSL import crypto


crypto.PKey().generate_key(type=crypto.TYPE_DSA, bits=4096)
