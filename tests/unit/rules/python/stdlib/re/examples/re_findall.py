# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 11
# end_column: 18
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.findall(pattern, string)
