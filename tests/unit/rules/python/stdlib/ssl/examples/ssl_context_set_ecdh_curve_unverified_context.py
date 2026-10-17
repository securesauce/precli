# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 23
# end_column: 35
import ssl


context = ssl._create_unverified_context()  # suppress: PY017
context.set_ecdh_curve("prime192v1")
