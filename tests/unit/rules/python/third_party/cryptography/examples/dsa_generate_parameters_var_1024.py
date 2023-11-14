# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 24
# end_column: 31
from cryptography.hazmat.primitives.asymmetric import dsa


keysize = 1024
dsa.generate_parameters(keysize)
