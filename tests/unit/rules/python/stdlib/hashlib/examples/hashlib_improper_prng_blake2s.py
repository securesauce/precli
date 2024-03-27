# level: WARNING
# start_line: 12
# end_line: 12
# start_column: 27
# end_column: 31
import hashlib
from random import randbytes


data = b"super-secret-data"
salt = randbytes(16)
hashlib.blake2s(data, salt=salt)
