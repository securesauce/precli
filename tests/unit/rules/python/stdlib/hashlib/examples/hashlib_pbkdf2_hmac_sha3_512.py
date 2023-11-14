# level: NONE
import hashlib


our_app_iters = 500_000
hashlib.pbkdf2_hmac("sha3_512", b"password", b"bad salt" * 2, our_app_iters)
