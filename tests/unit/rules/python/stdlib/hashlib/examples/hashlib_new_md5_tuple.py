# level: ERROR
# start_line: 10
# end_line: 10
# start_column: 12
# end_column: 23
import hashlib


test_tup = (0, None, "blah", "md5")
hashlib.new(test_tup[3])
