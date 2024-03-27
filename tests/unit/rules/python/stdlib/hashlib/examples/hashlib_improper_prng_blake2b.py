# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 27
# end_column: 31
import hashlib
import ssl


data = b"super-secret-data"
salt = ssl.RAND_bytes(16)
hashlib.blake2b(data, salt=salt)
