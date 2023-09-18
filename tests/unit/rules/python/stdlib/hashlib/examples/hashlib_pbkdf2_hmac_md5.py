import hashlib


our_app_iters = 500_000
hashlib.pbkdf2_hmac("md5", b"password", b"bad salt" * 2, our_app_iters)
