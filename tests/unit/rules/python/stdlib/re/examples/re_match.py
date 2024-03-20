# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 9
# end_column: 16
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.match(pattern, string)
