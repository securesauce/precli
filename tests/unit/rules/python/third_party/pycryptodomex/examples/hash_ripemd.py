# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 4
# end_column: 14
from Cryptodome.Hash import RIPEMD


h = RIPEMD.new()
h.update(b"Hello")
h.hexdigest()
