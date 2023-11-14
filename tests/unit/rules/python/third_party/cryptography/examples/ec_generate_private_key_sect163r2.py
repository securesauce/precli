# level: WARNING
# start_line: 9
# end_line: 9
# start_column: 27
# end_column: 36
from cryptography.hazmat.primitives.asymmetric import ec


ec.generate_private_key(ec.SECT163R2)
