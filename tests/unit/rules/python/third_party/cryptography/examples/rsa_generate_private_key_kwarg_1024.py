# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 57
# end_column: 61
from cryptography.hazmat.primitives.asymmetric import rsa


rsa.generate_private_key(public_exponent=65537, key_size=1024)
