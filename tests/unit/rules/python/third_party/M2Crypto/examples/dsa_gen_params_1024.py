# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 25
# end_column: 29
from M2Crypto import DSA


new_key = DSA.gen_params(1024)
