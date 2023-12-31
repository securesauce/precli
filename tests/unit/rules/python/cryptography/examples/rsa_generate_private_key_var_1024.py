# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 42
# end_column: 49
from cryptography.hazmat.primitives.asymmetric import rsa


public_exponent = 65537
keysize = 1024
rsa.generate_private_key(public_exponent, keysize)
