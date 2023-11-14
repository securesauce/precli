# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 33
# end_column: 37
from cryptography.hazmat.primitives.asymmetric import dsa


dsa.generate_parameters(key_size=1024)
