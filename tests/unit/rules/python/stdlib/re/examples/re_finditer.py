# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 12
# end_column: 19
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.finditer(pattern, string)
