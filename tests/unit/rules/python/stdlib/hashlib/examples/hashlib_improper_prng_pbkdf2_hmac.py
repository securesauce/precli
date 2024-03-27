# level: WARNING
# start_line: 13
# end_line: 13
# start_column: 58
# end_column: 62
import hashlib
import ssl


password = b"my_secure_password"
salt = ssl.RAND_bytes(16)
our_app_iters = 500_000
hashed_password = hashlib.pbkdf2_hmac("sha256", password, salt, our_app_iters)
