# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 32
# end_column: 36
from cryptography.hazmat.primitives.asymmetric import rsa


rsa.generate_private_key(65537, 1024)
