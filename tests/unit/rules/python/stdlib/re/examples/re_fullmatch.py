# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 13
# end_column: 20
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.fullmatch(pattern, string)
