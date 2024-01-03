# level: ERROR
# start_line: 9
# end_line: 9
# start_column: 4
# end_column: 11
from Cryptodome.Hash import MD4


h = MD4.new()
h.update(b"Hello")
h.hexdigest()
