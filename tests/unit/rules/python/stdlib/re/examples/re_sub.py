# level: ERROR
# start_line: 11
# end_line: 11
# start_column: 7
# end_column: 14
import re


pattern = r"(a+)+"
string = "aaaaaaaaaaaaaaaaaaaaaaaa!"
re.sub(pattern, print, string)
