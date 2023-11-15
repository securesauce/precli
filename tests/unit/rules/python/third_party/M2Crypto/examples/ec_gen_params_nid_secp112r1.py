# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 27
# end_column: 40
from M2Crypto import EC


new_key = EC.gen_params(EC.NID_secp112r1)
