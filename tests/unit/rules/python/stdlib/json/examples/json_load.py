# level: WARNING
# start_line: 11
# end_line: 11
# start_column: 0
# end_column: 9
import json
from io import StringIO


io = StringIO('["streaming API"]')
json.load(io)
