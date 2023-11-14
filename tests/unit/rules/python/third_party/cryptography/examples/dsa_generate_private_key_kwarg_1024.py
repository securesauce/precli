# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 34
# end_column: 38
from cryptography.hazmat.primitives.asymmetric import dsa


dsa.generate_private_key(key_size=1024)
