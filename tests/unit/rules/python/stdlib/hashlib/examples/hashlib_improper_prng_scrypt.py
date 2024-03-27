# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 48
# end_column: 52
import hashlib
import random


password = b"my_secure_password"
salt = random.randbytes(16)
hashed_password = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
