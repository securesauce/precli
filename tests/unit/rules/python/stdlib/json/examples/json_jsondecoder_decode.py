# level: WARNING
# start_line: 10
# end_line: 10
# start_column: 0
# end_column: 14
import json


decoder = json.JSONDecoder()
decoder.decode('["foo", {"bar":["baz", null, 1.0, 2]}]')
