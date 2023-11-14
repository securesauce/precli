# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 25
# end_column: 32
from cryptography.hazmat.primitives.asymmetric import dsa


keysize = 1024
dsa.generate_private_key(keysize)
